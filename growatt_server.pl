#!/usr/bin/perl
#
# Inspired by     : https://github.com/sciurius/Growatt-WiFi-Tools
#                   https://github.com/aaronjbrown/PyGrowatt
#                   https://gitlab.com/jeroenrnl/nrg
# Author          : Mario Stephan
# Created On      : 2021-03-26
#
# Copyright (c) 2021 Mario Stephan <mstephan@shared-files.de>
# Under MIT License (http://www.opensource.org/licenses/mit-license.php)
# https://github.com/knowthelist/ftui/Growatt-server
#
################################################################
#
# Local server for Growatt WiFi.
#
# The Growatt WiFi module communicates with the Growatt server
# (server.growatt.com, port 5279). This server can run
# as a standalone server for data logging without
# involving the Growatt servers.
#
#
# Data packages that contain energy data from the data logger is
# sent via MQTT.
#
# Usage:
#
# perl growatt_server.pl
# It will listen to port 5279.
#
# Using the Growatt WiFi module administrative interface, go to the
# "STA Interface Setting" and change "Server Address" (default:
# server.growatt.com) to the name or ip of the system running the
# your server.
# Reboot the WiFi module and re-visit the "STA Interface Setting" page
# to verify that the "Server Connection State" is "Connected".
#
#
################################################################

use warnings;
use strict;
use Getopt::Long 2.13;
use Data::Hexify;
use Net::MQTT::Simple;
use IO::Socket::INET;
use IO::Select;
use IO::Handle;
use Proc::Daemon;
use POSIX qw/strftime/;
use Time::Local;

use constant {
    MSG_TYPE_ANNOUNCE      => 0x03,
    MSG_TYPE_DATA          => 0x04,
    MSG_TYPE_PING          => 0x16,
    MSG_TYPE_CONFIG        => 0x18,
    MSG_TYPE_QUERY         => 0x19,
    MSG_TYPE_REBOOT        => 0x20,
    MSG_TYPE_BUFFERED_DATA => 0x50,
};

################ Common stuff ################

# Command line options.
my $local_port = 5279;    # local port.
my $timeout;              # 30 minutes
my $is_deamon = 0;
my $debug     = 0;        # debugging (currently default)

# Process command line options.
app_options();

# Post-processing.
$timeout = 300;

# CRC
my @crc16_table = generate_crc16_table();

# MQTT
my $mqtt_server           = 'localhost:1883';
my $mqtt_username         = '';
my $mqtt_password         = '';
my $mqtt_client_id_prefix = 'PV_GROWATT_';

################ Deamonize ################

my $continue = 1;
if ($is_deamon) {
    Proc::Daemon::Init;
    $SIG{TERM} = sub {
        print "TERM received";
        $continue = 0;
    };

    open( SYSLOG, "| /usr/bin/logger -t growatt" ) or die("syslog problem $!");
    *STDERR = *SYSLOG;
    autoflush STDERR 1;
}

################ Main Loop ################

my $ioset = IO::Select->new;
my %socket_map;

$| = 1;    # flush standard output

my $server;
my $identified;

print( ts(), "\tStarting Growatt ", " server", " on 0.0.0.0:$local_port\n" );
$server = new_server( '0.0.0.0', $local_port );
$ioset->add($server);

my $busy;
while ($continue) {
    my @sockets = $ioset->can_read($timeout);
    unless (@sockets) {
        if ( !$continue ) {
            print( "==== ", ts(), "\tTIMEOUT -- TERMINATING ====\n\n" );
            exit 1;
        }
        else {
            print( "==== ", ts(), "\tTIMEOUT -- RETRY ====\n\n" );
            next;
        }
    }
    $busy = 1;
    for my $socket (@sockets) {
        if ( $socket == $server ) {
            new_connection($server);
        }
        else {
            next unless exists $socket_map{$socket};
            my $dest = $socket_map{$socket};
            my $buffer;
            my $len = $socket->sysread( $buffer, 4096 );
            if ($len) {

                # request from client received
                print( ts(), "\t======= CLIENT ==== REQUEST =====\n" )
                  if $debug;
                print( "RAW\n", Hexify( \$buffer ), "\n" ) if $debug > 3;

                while ( my $msg = split_message( \$buffer ) ) {
                    foreach ( process_message( $socket, $msg ) ) {

                        # server replies to client
                        print( ts(), "\t======= SERVER ==== REPLY =====\n" )
                          if $debug;
                        print( "RAW\n", Hexify( \$_ ), "\n" ) if $debug > 3;
                        $dest->syswrite($_);
                    }
                }
            }
            else {
                close_connection($socket);
            }
        }
    }
}

################ Subroutines ################

sub new_server {
    my ( $host, $port ) = @_;
    my $server = IO::Socket::INET->new(
        LocalAddr => $host,
        LocalPort => $port,
        ReuseAddr => 1,
        Listen    => 100
    ) || die "Unable to listen on $host:$port: $!";
}

sub new_connection {
    my $server = shift;

    my $client    = $server->accept;
    my $client_ip = client_ip($client);

    print( ts(), "\tConnection from $client_ip accepted\n" ) if $debug;

    $ioset->add($client);
    $socket_map{$client} = $client;
}

sub close_connection {
    my $client    = shift;
    my $client_ip = client_ip($client);

    $ioset->remove($client);
    delete $socket_map{$client};
    $client->close;

    print( ts(), "\tConnection from $client_ip closed\n" ) if $debug;
}

sub client_ip {
    my $client = shift;
    return ( eval { $client->peerhost } || $ENV{REMOTE_ADDR} || "?.?.?.?" );
}

sub ts {
    my @tm = localtime(time);
    sprintf(
        "%04d-%02d-%02d %02d:%02d:%02d",
        1900 + $tm[5],
        1 + $tm[4],
        @tm[ 3, 2, 1, 0 ]
    );
}

sub split_message {
    my ($bufref) = @_;
    my $buffer_length = length($$bufref);

    print( "split_message", "\t", "buffer_length", "\t", $buffer_length, "\n" )
      if $debug > 3;

    if ( $buffer_length > 6 ) {

        my ( $protocol_id, $size ) = unpack( "x2nn", $$bufref );

        print( "split_message", "\t", "protocol_id", $protocol_id, "\n" )
          if $debug > 3;
        print( "split_message", "\t", "message size", $size, "\n" )
          if $debug > 3;

        if ( $protocol_id >= 5 ) {
            $size += 2;    # version > 4 has a trailing CRC
        }

        if ( $protocol_id && $buffer_length - 5 >= $size ) {
            my $ret_value = substr( $$bufref, 0, $size + 6 );
            $$bufref = substr( $$bufref, $size + 6 );
            return $ret_value;
        }
        else {
            print(  "Invalid message, expected "
                  . $size
                  . ", got "
                  . $buffer_length - 5 );
            $$bufref = "";
            return;
        }
    }
}

#  ------------------------------------------------------------------
#   Growatt Modbus Socket Frame
#
#   [         MBAP Header         ] [ Function Code] [ Data ] [CRC]\
#   [ tid ][ pid ][ length ][ uid ]
#      2b     2b       2b       1b           1b         (N-2)b   2b

sub decode_message {
    my ($frame) = @_;
    my ( $msg_id, $protocol_id, $length, $unit_id, $type ) =
      unpack( "nnnCC", $frame );
    my $crc        = unpack( "n", bytes::substr( $frame, -2 ) );
    my $frame_part = bytes::substr( $frame, 0, -2 );
    my $data       = _xor( bytes::substr( $frame_part, 8 ) );

    print(
        "decode_message\tmessage CRC\t",
        $crc,              "\t calculated CRC\t",
        _crc($frame_part), "\n"
    ) if $debug > 3;

    # check CRC
    if ( !( _crc($frame_part) == $crc ) ) {
        print("crc is not ok, skip frame\n");
        return;
    }

    return {
        msg_id      => $msg_id,
        protocol_id => $protocol_id,
        length      => $length,
        unit_id     => $unit_id,
        type        => $type,
        data        => $data,
    };
}

sub process_message {
    my ( $socket, $frame ) = @_;
    my $ts      = ts();
    my $message = decode_message($frame);

    if ( !$message ) {
        return;
    }

    print( "process_message", "\t", "type", "\t",
        sprintf( "0x%02X", $message->{type} ), "\n" )
      if $debug > 2;
    print( "process_message", "\t", "data", "\n", Hexify( \$message->{data} ) )
      if $debug > 2;

    # PING.
    if ( $message->{type} == MSG_TYPE_PING ) {
        my $request = decode_ping_request($message);
        print( $ts, "\t", "== received PING from ",
            $request->{serial}, ", sending reply ==\n\n" )
          if $debug;
        return create_reply( MSG_TYPE_PING, $message,
            pack( "a10", $request->{serial} ) );
    }

    # ANNOUNCE
    if ( $message->{type} == MSG_TYPE_ANNOUNCE ) {
        my $request = decode_announce_request($message);
        my @reply   = ();
        print( $ts, "\t", "== received ANNOUNCE from ",
            $request->{serial},   " for inverter ",
            $request->{inverter}, ", sending reply ==\n\n"
        ) if $debug;
        print "time diff:", $request->{time_diffence}, "\n" if $debug > 2;

        if ( $request->{time_diffence} > 60 ) {
            print "diff > 60 => correct time on client now.\n" if $debug > 2;
            my $date = strftime "%Y-%m-%d %H:%M:%S", localtime time;
            push @reply,
              create_reply( MSG_TYPE_CONFIG,
                $message,
                pack( "A[10]CCCCA*",
                    $request->{serial}, 0x0,           0x1f,
                    0x0,                length($date), $date )
              );
        }

        if ($identified) {
            push @reply,
              create_reply( MSG_TYPE_ANNOUNCE, $message, pack( "C", 0x0 ) );
        }
        else {
            push @reply,
              create_reply( MSG_TYPE_ANNOUNCE, $message, pack( "C", 0x0 ) );
            push @reply,
              create_reply( MSG_TYPE_QUERY, $message,
                pack( "A[10]C*", $request->{serial}, 0x00, 0x04, 0x00, 0x1F ) );
        }

        return @reply;
    }

    # QUERY reply (the requested CONFIGs)
    if ( $message->{type} == MSG_TYPE_QUERY ) {
        my $request = decode_query_request($message);
        $identified++;

        print( "CONFIG of ", $request->{serial}, "\t",
            sprintf( "0x%02X", $request->{config_id} ),
            "\t", $request->{config_value}, "\n" )
          if $debug;

        return;    # ignore
    }

    # PV DATA
    if ( $message->{type} == MSG_TYPE_DATA ) {
        my $request = decode_data_request($message);

        print( $ts, "\t", "== received DATA from ",
            $request->{serial}, ", sending reply ==\n\n" )
          if $debug;

        print_pv_data($request);
        publish_MQTT($request);

        return create_reply( MSG_TYPE_DATA, $message, pack( "C", 0x0 ) );
    }

    # PV Buffered DATA
    if ( $message->{type} == MSG_TYPE_BUFFERED_DATA ) {
        my $request = decode_data_request($message);

        print( $ts, "\t", "== received BUFFERED_DATA from ",
            $request->{serial}, ", sending reply ==\n\n" )
          if $debug;

        print_pv_data($request);

        return create_reply( MSG_TYPE_BUFFERED_DATA, $message,
            pack( "C", 0x0 ) );
    }

    # Unhandled.
    print( $ts, "\t", "== unhandled message ==\n\n" ) if $debug;
    return;
}

sub decode_ping_request {
    my ($message) = @_;
    my $serial = unpack( "A10", $message->{data} );

    return { serial => $serial };
}

sub decode_announce_request {
    my ($message) = @_;
    my ( $serial, $inverter ) = unpack( "a10 x20 a10", $message->{data} );
    my ( $year, $month, $day ) =
      unpack( "nnn", substr( $message->{data}, 161 ) );
    my ( $hour, $min, $sec ) = unpack( "nnn", substr( $message->{data}, 167 ) );
    my @tm = localtime(time);
    my $now =
      timelocal( $tm[0], $tm[1], $tm[2], $tm[3], $tm[4], 1900 + $tm[5] );
    my $time = timelocal( $sec, $min, $hour, $day, $month - 1, $year );

    return {
        serial        => $serial,
        inverter      => $inverter,
        time_diffence => abs( $now - $time )
    };
}

sub decode_query_request {
    my ($message) = @_;
    my ( $serial, $config_id, $config_value ) =
      unpack( "a10 x21 C x2 a*", $message->{data} );

    return {
        serial       => $serial,
        config_id    => $config_id,
        config_value => $config_value
    };
}

sub decode_data_request {
    my ($message) = @_;

    my ( $serial, $inverter ) = unpack( "a10 x20 a10", $message->{data} );
    my ( $year, $month, $day ) =
      unpack( "CCC", substr( $message->{data}, 60 ) );
    my ( $hour, $min, $sec ) = unpack( "CCC", substr( $message->{data}, 63 ) );
    my ($Ppv) = unpack( "N", substr( $message->{data}, 73 ) );
    my ( $Vpv1, $Ipv1, $Ppv1 ) =
      unpack( "nnN", substr( $message->{data}, 77 ) );
    my ( $Pac, $Fac ) = unpack( "Nn", substr( $message->{data}, 117 ) );
    my ( $Vac1, $Iac1, $Pac1 ) =
      unpack( "nnN", substr( $message->{data}, 123 ) );
    my ($Eac_today) = unpack( "N", substr( $message->{data}, 169 ) );
    my ($Eac_total) = unpack( "N", substr( $message->{data}, 177 ) );

    return {
        serial    => $serial,
        inverter  => $inverter,
        month     => $month,
        day       => $day,
        hour      => $hour,
        sec       => $sec,
        year      => $year,
        Ppv       => sprintf( "%.1f", $Ppv / 10 ),
        Vpv1      => sprintf( "%.1f", $Vpv1 / 10 ),
        Ipv1      => sprintf( "%.1f", $Ipv1 / 10 ),
        Ppv1      => sprintf( "%.1f", $Ppv1 / 10 ),
        Pac       => sprintf( "%.1f", $Pac / 10 ),
        Fac       => $Fac / 100,
        Vac1      => sprintf( "%.1f", $Vac1 / 10 ),
        Iac1      => sprintf( "%.1f", $Iac1 / 10 ),
        Pac1      => sprintf( "%.1f", $Pac1 / 10 ),
        Eac_today => sprintf( "%.1f", $Eac_today / 10 ),
        Eac_total => sprintf( "%.1f", $Eac_total / 10 ),
        timestamp => sprintf(
            "%04d-%02d-%02d %02d:%02d:%02d",
            2000 + $year,
            $month, $day, $hour, $min, $sec
        ),
    };
}

sub create_reply {
    my ( $type, $message, $data ) = @_;
    my $reply = pack( "nnnCC",
        $message->{msg_id},
        $message->{protocol_id},
        length($data) + 2,
        $message->{unit_id}, $type );

    if ( $message->{protocol_id} >= 5 ) {
        $reply .= _xor($data);
        $reply .= pack( "n", _crc($reply) );
    }
    else {
        $reply .= $data;
    }
    return $reply;
}

sub _xor {
    my ($data) = @_;
    my $key    = "Growatt";
    my $reply  = "";
    for ( my $i = 1 ; $i <= length($data) ; $i++ ) {
        my $nth_data = substr( $data, $i - 1, 1 );
        my $nth_key  = substr( $key, ( $i % length($key) ) - 1, 1 );
        $reply .= chr( ord($nth_data) ^ ord($nth_key) );
    }
    return $reply;
}

sub generate_crc16_table {
    my @result = ();
    foreach my $byte ( 0 .. 255 ) {
        my $crc = 0x0000;
        foreach my $bit ( 0 .. 7 ) {
            if ( ( $byte ^ $crc ) & 0x0001 ) {
                $crc = ( $crc >> 1 ) ^ 0xa001;
            }
            else {
                $crc >>= 1;
            }
            $byte >>= 1;
        }
        push @result, $crc;
    }
    return @result;
}

sub _crc {
    my ($data) = @_;
    my $crc    = 0xffff;
    my @data   = unpack( "C*", $data );

    foreach (@data) {
        $crc = @crc16_table[ ( $_ ^ $crc ) & 0xff ] ^ ( $crc >> 8 & 0xff );
    }
    return $crc & 0xffff;
}

sub print_pv_data {
    my ($data) = @_;

    print "timestamp: ", $data->{timestamp}, "\n";
    print "Eac_today: ", $data->{Eac_today}, "\n";
    print "Eac_total: ", $data->{Eac_total}, "\n";

    print "Ppv1: ", $data->{Ppv1}, "\n";
    print "Ipv1: ", $data->{Ipv1}, "\n";
    print "Vpv1: ", $data->{Vpv1}, "\n";

    print "Fac: ",  $data->{Fac},  "\n";
    print "Vac1: ", $data->{Vac1}, "\n";
    print "Iac1: ", $data->{Iac1}, "\n";
    print "Pac1: ", $data->{Pac1}, "\n";
}

sub publish_MQTT {
    my ($data) = @_;

    package Net::MQTT::Simple::ID;

    our @ISA         = 'Net::MQTT::Simple';
    our $inverter_id = $data->{inverter};

    # use a fix MQTT client id
    sub _client_identifier {
        return $mqtt_client_id_prefix . $inverter_id;
    }

    # Allow unencrypted connection with credentials
    $ENV{MQTT_SIMPLE_ALLOW_INSECURE_LOGIN} = 1;

    # Connect to server (broker)
    my $mqtt = Net::MQTT::Simple::ID->new($mqtt_server);

    # Depending if authentication is required, login to the broker
    if ( $mqtt_username and $mqtt_password ) {
        $mqtt->login( $mqtt_username, $mqtt_password );
    }

    # Publish PV data
    $mqtt->publish( "Eac_today", $data->{Eac_today} );
    $mqtt->publish( "Eac_total", $data->{Eac_total} );
    $mqtt->publish( "Ppv1",      $data->{Ppv1} );
    $mqtt->publish( "Ipv1",      $data->{Ipv1} );
    $mqtt->publish( "Vpv1",      $data->{Vpv1} );
    $mqtt->publish( "Vac1",      $data->{Vac1} );
    $mqtt->publish( "Iac1",      $data->{Iac1} );
    $mqtt->publish( "Pac1",      $data->{Pac1} );

    $mqtt->disconnect();
}

################ Command line options ################

sub app_options {
    my $help  = 0;    # handled locally
    my $ident = 0;    # handled locally

    if (
        !GetOptions(
            'listen=i'      => \$local_port,
            'timeout=i'     => \$timeout,
            'inetd|systemd' => \$is_deamon,
            'help|?'        => \$help,
            'debug=i'       => \$debug,
        )
        or $help
      )
    {
        app_usage(2);
    }
    app_ident() if $ident;

    $local_port ||= 5279;
}

sub app_usage {
    my ($exit) = @_;
    app_ident();
    print STDERR <<EndOfUsage;
Usage: $0 [options]
    --listen=NNNN	Local port to listen to (must be $local_port)
    --timeout=NNN	Timeout
    --inetd  --systemd	Running from inetd/systemd
    --help		This message
    --debug=N		More verbose information
 

EndOfUsage
    exit $exit if defined $exit && $exit != 0;
}
