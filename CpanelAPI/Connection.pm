package CpanelAPI::Connection;

# In the context of this module, a connection object does not actually
# represent a connection (the API is stateless, so "connection" is meaningless)
# but rather represents connection and authentication data that will be used
# to interact with the API.
#
# It's not a User Agent. It's not a truck. It's not a series of tubes. And it's not people.

sub new {
    my ($class, $args) = @_;
    my $self = {
        'hostname' => $args{'hostname'},
        'username' => $args{'username'},
        'protocol' => 'https',
    }
    return bless $self, $class;
}

# Below here goes all the code to choose the authentication method, and add
# supporting data to $self.
# I don't currently have this code, because it's in a newer branch than I have
# on this workstation right now.

sub create_user_session {
    my ($self, $args) = @_;
    # Obviously... create a user session and return that connection object.
}
