#!/usr/bin/env perl

use Mojolicious::Lite;
use Mojo::Asset::File;
use Mojo::JSON;
use Net::Twitter::Lite::WithAPIv1_1;
use Mojo::IOLoop;

# access config and delete secret stuff from stash
plugin 'Config';
my $app_secret      = app->config('app_secret');
my $consumer_secret = app->config('consumer_secret');
delete app->config->{$_} for qw(app_secret consumer_secret);

# hypnotoad production server configuration
app->config(hypnotoad => {listen => ['http://*:3456']});

# set secret phrase for secure signed cookies
app->secret($app_secret);

# access users json file helpers
helper json     => sub { Mojo::JSON->new };
helper users    => sub {
    my $c => shift;

    # prepare
    my $filename = app->home->rel_file(app->config('users_file_name'));

    # write new users data
    if (my $data = shift) {
        open my $file, '>', $filename or die $!;
        print $file app->json->encode($data);
    }

    # read users data
    else {
        open my $file, '<', $filename or die $!;
        return app->json->decode(do {local $/; <$file>});
    }
};

# prepare twitter
my $twitter = Net::Twitter::Lite::WithAPIv1_1->new(
    consumer_key    => app->config('consumer_key'),
    consumer_secret => $consumer_secret,
);
helper twitter => sub { $twitter };

### web app shizzle starts here

# start here: overview if logged in
get '/' => sub {
    my $self = shift;

    # logged in: overview page
    return $self->redirect_to('overview')
        if defined $self->session('user_id');
} => 'index';

# authoriza via twitter
get '/login' => sub {
    my $self = shift;

    # generate auth URL
    my $cb  = $self->url_for('callback')->to_abs;
    my $url = eval { $self->twitter->get_authorization_url(callback => $cb) };

    # error handling
    if ($@) {
        $self->flash(message => "$@");
        return $self->redirect_to('message');
    }

    # save request token in a session
    $self->session(
        oauth_token         => $self->twitter->request_token,
        oauth_token_secret  => $self->twitter->request_token_secret,
    );

    # redirect to twitter for authorization
    $self->redirect_to($url);
};

get '/callback' => sub {
    my $self = shift;

    # save the verifier
    my $verifier = $self->param('oauth_verifier');

    # set token from session
    $self->twitter->request_token($self->session('oauth_token'));
    $self->twitter->request_token_secret($self->session('oauth_token_secret'));

    # request access token and user data
    my ($access_token, $access_token_secret, $user_id, $screen_name) = eval {
        $self->twitter->request_access_token(verifier => $verifier)
    };

    # error handling
    if ($@) {
        $self->flash(message => "$@");
        return $self->redirect_to('message');
    }

    # successfully logged in
    $self->session(user_id => $user_id);

    # user data lookup
    my $users   = $self->users // {};
    my $user    = $users->{$user_id} // {};

    # new user: init
    unless (keys %$user) {
        $user->{connected}  = 1;
        $user->{messages}   = [
            'This is a very cool twitter message',
            'Yay, cool stuff, it works!',
        ];
    }

    # update
    $user->{access_token}           = $access_token;
    $user->{access_token_secret}    = $access_token_secret;
    $user->{screen_name}            = $screen_name;
    $users->{$user_id} = $user;
    $self->users($users);

    # go to overview
    $self->redirect_to('index');
};

# messages
get '/message' => sub {
    my $self = shift;

    # get message
    my $msg = $self->flash('message');

    # no message
    unless ($msg) {
        $self->res->code(403);
        return $self->render(text => 'Forbidden!');
    }

    # display message
    $self->stash(message => $msg);
};

# users must be logged in for the following actions
under sub {
    my $self = shift;

    # not logged in
    my $user_id = $self->session('user_id');
    unless (defined $user_id) {
        $self->res->code(401);
        $self->render(text => 'Unauthorized');
        return 0;
    }

    # no user data: shouldn't happen
    my $users = $self->users // {};
    unless (exists $users->{$user_id}) {
        $self->res->code(401);
        $self->render(text => "You don't exist");
        return 0;
    }

    # logged in: prepare user data
    $self->stash(
        users   => $users,
        user    => $users->{$user_id},
    );
    return 1;
};

# overview page: not much to do
get '/overview';

# update user settings
post '/update' => sub {
    my $self = shift;

    # merge settings
    my $user = $self->stash('user');
    $user->{connected}  = $self->param('connected');
    $user->{messages}   = [ split /[\r\n]+/ => $self->param('messages') ];

    # update settings
    $self->users($self->stash('users'));

    # done
    $self->flash(message => 'Done.');
    $self->redirect_to('message');
};

# logout: delete the user from session
get '/logout' => sub {
    my $self = shift;

    # delete user id from session
    delete $self->session->{user_id};

    # done
    $self->flash(message => 'You are now logged out. Bye!');
    $self->redirect_to('message');
};

### twitter posting stuff

# timer for tweets
sub update_time {
    my $next = shift;
    unless (defined $next) {
        my $min     = 16 * 60 * 60;
        my $max     = 32 * 60 * 60;
        $next    = $min + rand($max - $min);
    }
    Mojo::IOLoop->timer($next => sub { tweet(); update_time() });
}

# invoke tweeting
sub tweet {
    
    # iterate connected users
    my $users = app->users;
    while (my ($user_id, $user) = each %$users) {
        next unless $user->{connected};

        # tweet
        my $message = ${$user->{messages}}[rand @{$user->{messages}}] // '?';
        app->twitter->access_token($user->{access_token});
        app->twitter->access_token_secret($user->{access_token_secret});
        eval { app->twitter->update($message) };

        # error handling
        app->log->error("$@") and next if $@;

        # log
        app->log->info("$user->{screen_name} status updated.");
    }
}

# update once
update_time(15);

app->start;
__DATA__

@@ index.html.ep
% layout 'default';
% title 'Welcome';
%=t h1 => 'Welcome to Tweet Sometimes (Perl)!'
%=t p => begin
    %= link_to 'Login with twitter' => 'login'
% end

@@ message.html.ep
% layout 'default';
% title 'Message for you!';
%=t h1  => 'Message for you!'
%=t p   => $message
%=t p => begin
    %= link_to 'Go to home page' => 'index'
% end

@@ overview.html.ep
% layout 'default';
% title 'Overview';
% param connected   => $user->{connected};
% param messages    => join "\n" => @{$user->{messages}};
%=t h1 => 'Welcome ' . $user->{screen_name} . '!'
%= form_for update => begin
    %=t p => begin
    Tweet Sometimes (Perl) is
        %= radio_button connected => 1, id => 'connected'
        %=t 'label', for => 'connected', 'connected'
        %= radio_button connected => 0, id => 'disconnected'
        %=t 'label', for => 'disconnected', 'disconnected'
    % end
    %=t p => begin
        %=t 'label', for => 'messages', 'Your messages:'
        %=t 'br'
        %= text_area 'messages', cols => 140, rows => 20;
    % end
    %=t p => begin
        %= submit_button 'Update'
    % end
% end
%= form_for logout => begin
    %=t p => begin
        %= submit_button 'Logout'
    % end
% end

@@ layouts/default.html.ep
<!DOCTYPE html>
<html><head><title><%= title %> - Tweet Sometimes (Perl)</title></head><body>
%= content
</body></html>
