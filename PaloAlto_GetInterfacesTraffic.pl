#!/usr/bin/perl  
#===========================================
#Script GET Trafic by interfaces PALOALTO
#auteur : Arnaud Zobec
#date : 28/05/2015
#version : 002.000
#===========================================
use strict;
use warnings;
use LWP::UserAgent;  
use HTTP::Request;
use XML::Simple;

my $hostname= "xx.xx.xx.xx"; #Firewall IP
my $httpskey="xxxxxxxxxxxxxx"; # example 'vcxverdzaduhza=='
my $un = 1;
my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
my $input_tunnel_one = 0;
my $input_tunnel_two = 0;
my $input_ipsec_tunnel = 0;
my $output_tunnel_one = 0;
my $output_tunnel_two = 0;
my $output_ipsec_tunnel = 0;
my $URL = 'https://'.$hostname.'/api/?type=report&reporttype=dynamic&reportname=custom-dynamic-report&cmd=<type><threat><aggregate-by><member>threatid</member><member>severity</member></aggregate-by><values><member>repeatcnt</member></values></threat></type><period>last-15-minutes</period><topn>10</topn><topm>10</topm><caption>Threat-Last-15Mn</caption>&key='.$httpskey.'';

#=================================
#Récupération des Gb par tunnel
#=================================

my $header = HTTP::Request->new(GET => $URL);  
my $request = HTTP::Request->new('GET', $URL, $header);  
my $response = $ua->request($request);  

my $parser = XML::Simple->new( KeepRoot => 1 );
my $xml_string;
if ($response->is_success)
{  
	$xml_string = $response->content;
}
elsif ($response->is_error)
{  
	print "Error:$URL\n";  
	print $response->error_as_HTML;  
}
my $doc_two = $parser->XMLin($xml_string);

#===================
#Parsing de la table de hash (see Dumper datas en cas de bug)
my $entry = $doc_two->{response}->{result}->{ifnet}->{entry};
foreach my $tunnel (keys(%{$entry}))
{
	if ($tunnel eq "tunnel")
	{
		#Récupération du counter Bytes du tunnel un
		$input_tunnel_one = $doc_two->{response}->{result}->{ifnet}->{entry}{$tunnel}->{ibytes};
		$output_tunnel_one = $doc_two->{response}->{result}->{ifnet}->{entry}{$tunnel}->{obytes};
	}
	elsif ($tunnel eq "tunnel.172")
	{
		#Récupération du counter Bytes du tunnel deux
		$input_tunnel_two = $doc_two->{response}->{result}->{ifnet}->{entry}{$tunnel}->{ibytes};
		$output_tunnel_two = $doc_two->{response}->{result}->{ifnet}->{entry}{$tunnel}->{obytes};
	}
	elsif ($tunnel =~ "tunnel")
	{
		#Récupération du counter Bytes du tunnel IPsec
		$input_ipsec_tunnel = $input_ipsec_tunnel + $doc_two->{response}->{result}->{ifnet}->{entry}{$tunnel}->{ibytes};
		$output_ipsec_tunnel = $output_ipsec_tunnel + $doc_two->{response}->{result}->{ifnet}->{entry}{$tunnel}->{obytes};
	}
}

#===================
#Affichage Final
print "input_tunnel_one:$input_tunnel_one output_tunnel_one:$output_tunnel_one input_tunnel_two:$input_tunnel_two output_tunnel_two:$output_tunnel_two input_ipsec_tunnel:$input_ipsec_tunnel output_ipsec_tunnel:$output_ipsec_tunnel\n";

#==================================
#FIN Récupération des Go par tunnel
#==================================