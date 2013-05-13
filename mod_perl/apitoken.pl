#!/usr/bin/perl

my $token_lifetime_seconds = 3600;

my %mimetypes = (
    "*"           => {
	"*"         => {handler => "json", mimetype => "application/json"},
    },
    "text"        => {
	"*"         => {handler => "plaintext", mimetype => "text/plain"},
	"html"      => {handler => "html", mimetype => "text/html"},
	"plain"     => {handler => "plaintext", mimetype => "text/plain"},
	"xml"       => {handler => "xml", mimetype => "text/xml"},
    },
    "application" => {
	"*"         => {handler => "json", mimetype => "application/json"},
	"xml"       => {handler => "xml", mimetype => "application/xml"},
	"xhtml+xml" => {handler => "xhtml", mimetype => "application/xhtml+xml"},
	"json"      => {handler => "json", mimetype => "application/json"},
    },
    );

use Digest::HMAC;
use Digest::MD5;
use IO::File;
use MIME::Base64 qw(decode_base64 encode_base64);
use Math::Random::Secure qw(irand);

die "apitoken only supports GET method" unless $ENV{'REQUEST_METHOD'} eq 'GET';

die "apitoken must be protected behind shibboleth authentication" unless $ENV{'AUTH_TYPE'} eq 'shibboleth';

die "apitoken requires eppn" unless $ENV{'eppn'} ne "";

my $user = $ENV{'eppn'};
my $shib_session_id = $ENV{'Shib-Session-ID'};

my $secret_key_file = $ENV{'HGI_API_SECRET_KEY_FILE'};
my $secret_key = load_secret_key($secret_key_file);

my $time = time(); 
my $expiration = $time + $token_lifetime_seconds;

my $salt = irand(); # returns 32-bit integer
my $message = $user . ':' . $expiration . ':' . $shib_session_id . ':' . $salt;
my $api_basic_login = b64enc($message);

my $hmac = Digest::HMAC->new($secret_key, "Digest::MD5");
$hmac->add($message);
my $mac = $hmac->b64digest;

my $api_basic_password = b64enc($mac);

my $api_access_token = b64enc($message . ':' . $mac);

my %accept;

foreach my $accept (split /\,/, $ENV{'HTTP_ACCEPT'}) {
    my ($mediarange, @params) = split /\;/, $accept;
    my $q = 1;
    foreach my $param (@params) {
	my ($key, $value) = split /\=/, $param;
	if($key eq 'q') {
	    $q = $value;
	}
    }
    push @{$accept{$q}}, $mediarange;
}

my @qs = sort {$b <=> $a} keys %accept;
foreach my $q (@qs) {
    foreach my $mediarange (@{$accept{$q}}) {
	my ($type, $subtype) = split /\//, $mediarange;
	if (exists($mimetypes{$type})) {
	    # we can handle this type
	    if (exists($mimetypes{$type}{$subtype})) {
		# we can handle this subtype
		print_output($api_basic_login, $api_basic_password, $api_access_token, $mimetypes{$type}{$subtype}{handler}, $mimetypes{$type}{$subtype}{mimetype});
		exit 0;
	    }
	}
    }
}

# FIXME: should respond with 406 error
print_output($api_basic_login, $api_basic_password, $api_access_token, "json", "application/json");
exit;

sub print_output {
    my $api_basic_login = shift;
    my $api_basic_password = shift;
    my $api_access_token = shift;
    my $handler = shift;
    my $mimetype = shift;
    
    print "Content-type: $mimetype\n";
    print "Cache-Control: no-store\n";
    print "Pragma: no-cache\n";
    print "\n";

    if($handler eq "plaintext") {
	print "access_token=".$api_access_token;
	print "&token_type=bearer";
	print "&api_basic_login=$api_basic_login";
	print "&api_basic_password=$api_basic_password";
    } elsif($handler eq "json") {
	print "{\n";
	print '"access_token": "' . $api_access_token . '"' . "\n";
	print '"token_type": "bearer"' . "\n";
	print '"api_basic_login": "' . $api_basic_login . '"' . "\n";
	print '"api_basic_password": "' . $api_basic_password . '"' . "\n";
	print "}\n";
    } elsif($handler eq "html") {
	print<<EOF;
<html>
  <head>
    <title>API Token</title>
  </head>
  <body>
    <dl>
      <dt>access_token</dt>
      <dd>$api_access_token</dd>
      <dt>token_type</dt>
      <dd>bearer</dd>
      <dt>api_basic_login</dt>
      <dd>$api_basic_login</dd>
      <dt>api_basic_password</dt>
      <dd>$api_basic_password</dd>
    </dl>
  </body>
</html>
EOF
    } elsif($handler eq "xhtml") {
	print<<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <title>API Token</title>
  </head>
  <body>
    <dl>
      <dt>access_token</dt>
      <dd>$api_access_token</dd>
      <dt>token_type</dt>
      <dd>bearer</dd>
      <dt>api_basic_login</dt>
      <dd>$api_basic_login</dd>
      <dt>api_basic_password</dt>
      <dd>$api_basic_password</dd>
    </dl>
  </body>
</html>
EOF
    } elsif($handler eq "xml") {
	print<<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<OAuth>
  <token_type>bearer</token_type>
  <access_token>$api_access_token</access_token>
  <api_basic_login>$api_basic_login</api_basic_login>
  <api_basic_password>$api_basic_password</api_basic_password>
</OAuth>
EOF
    }    
}

sub b64enc {
    my $raw = shift;
    my $b64 = encode_base64($raw);
    $b64 =~ s/[[:space:]]//g;
    return $b64;
}

sub load_secret_key {
    my $secret_key_file = shift;
    my $secret_key_fh = IO::File->new();
    die "apitoken could not open secret key file $secret_key_file" unless $secret_key_fh->open("<".$secret_key_file);
    
    local($/) = undef;  # slurp in everything from the file
    my $secret_key = decode_base64(<$secret_key_fh>);
    
    return $secret_key;
}
