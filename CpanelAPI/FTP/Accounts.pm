package CpanelAPI::Ftp::Accounts;

use CpanelAPI::URL;

sub new {
    my ( $class, $connection ) = @_;
    if ( !$connection ) { die 'No connection was provided.'; }
    if ( $connection->context != 'cpaneld' ) {
        die "$class only makes sense in cPanel's context.";
    }
    my $self = { 'connection' = $connection, };
    return bless $self, $class;
}

sub add {
    my ( $self, $args ) = @_;
    my $url = CpanelAPI::URL->new(
        {
            'connection' => $args->{'connection'},
            'api_class'  => 'UAPI',
            'module'     => 'Ftp',
            'function'   => 'add_ftp',
            'params_ref' => $args,
        }
    );

# The return needs to get checked. If fetching JSON data didn't work, we need to die here.
# Could this call itself die?
    return $url->do_the_thing();
}

sub remove {
}

sub list {
}

sub set_password {
}
