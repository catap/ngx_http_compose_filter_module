#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for compose filter module.

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(16);

$t->write_file_expand('nginx.conf', <<'EOF');

master_process off;
daemon         off;

events {
}

http {
    access_log    off;
    root          %%TESTDIR%%;

    client_body_temp_path  %%TESTDIR%%/client_body_temp;
    fastcgi_temp_path      %%TESTDIR%%/fastcgi_temp;
    proxy_temp_path        %%TESTDIR%%/proxy_temp;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /compose {
            compose on;

            add_header  X-Compose-Length  4000;
            add_header  X-Compose  /t1?1;
            add_header  X-Compose  /t1?2;
            add_header  X-Compose  /t1?3;
            add_header  X-Compose  /t1?4;

            empty_gif;
        }

        location /compose-big {
            compose on;

            add_header  X-Compose  /tbig?1;
            add_header  X-Compose  /tbig?2;
            add_header  X-Compose  /tbig?3;
            add_header  X-Compose  /tbig?4;

            empty_gif;
        }
    }
}

EOF

$t->write_file('t1',
	join('', map { sprintf "X%03dXXXXXX", $_ } (0 .. 99)));
$t->write_file('tbig', 'X' x (1 * 1024 * 1024));
$t->run();

###############################################################################

my $t1;

# normal requests

$t1 = http_get('/compose');
like($t1, qr/ 200 /, 'full reply');
like($t1, qr/Content-Length: 4000/, 'full reply length');
like($t1, qr/^(X[0-9]{3}XXXXXX){400}$/m, 'full reply content');

# various range requests

$t1 = http_get_range('/compose', 'Range: bytes=0-9');
like($t1, qr/206/, 'first bytes - 206 partial reply');
like($t1, qr/Content-Length: 10/, 'first bytes - correct length');
like($t1, qr/Content-Range: bytes 0-9\/4000/, 'first bytes - content range');
like($t1, qr/^X000X{6}$/m, 'first bytes - correct content');

$t1 = http_get_range('/compose', 'Range: bytes=-10');
like($t1, qr/ 206 /, 'final bytes - 206 partial reply');
like($t1, qr/Content-Length: 10/, 'final bytes - content length');
like($t1, qr/Content-Range: bytes 3990-3999\/4000/,
	'final bytes - content range');
like($t1, qr/^X099XXXXXX$/m, 'final bytes - correct content');

$t1 = http_get_range('/compose', 'Range: bytes=900-1099');
like($t1, qr/ 206 /, 'multi buffers - 206 partial reply');
like($t1, qr/Content-Length: 200/, 'multi buffers - content length');
like($t1, qr/Content-Range: bytes 900-1099\/4000/, 'multi buffers - content range');
like($t1, qr/^(X09[0-9]XXXXXX){10}(X00[0-9]XXXXXX){10}$/m,
	'multi buffers - correct content');

# big files

$t1 = http_get('/compose-big');
cmp_ok(length($t1), '>', 4 * 1024 * 1024, 'big files - correct length');

###############################################################################

sub http_get_range {
	my ($url, $extra) = @_;
	return http(<<EOF);
GET $url HTTP/1.1
Host: localhost
Connection: close
$extra

EOF
}

###############################################################################
