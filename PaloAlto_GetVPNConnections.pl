#!/usr/bin/perl  
#===========================================
#Script GET VPN - number of people connected
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
my $vpn_un = 0;
my $vpn_deux = 0;
my $vpn_trois = 0;
my $un = 1;
my $URL = 'https://'.$hostname.'/api/?type=report&reporttype=dynamic&reportname=custom-dynamic-report&cmd=<type><threat><aggregate-by><member>threatid</member><member>severity</member></aggregate-by><values><member>repeatcnt</member></values></threat></type><period>last-15-minutes</period><topn>10</topn><topm>10</topm><caption>Threat-Last-15Mn</caption>&key='.$httpskey.'';
my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });



#========================================
#Récupération du nombre de connexion VPN
#========================================

my $header = HTTP::Request->new(GET => $URL);  
my $request = HTTP::Request->new('GET', $URL, $header);  
my $response = $ua->request($request);  

my $xml_string;
if ($response->is_success){  
	$xml_string = $response->content;
}
elsif ($response->is_error){  
	print "Error:$URL\n";  
	print $response->error_as_HTML;  
}

my $parser = XML::Simple->new( KeepRoot => 1 );
my $doc = $parser->XMLin($xml_string);

foreach my $vpn_connexion(@{ $doc->{response}->{result}->{entry} })
{
	if($vpn_connexion->{domain} eq 'tunnel_un')
	{
		#Récupération nombre connectés tunnel un
		$vpn_deux = $vpn_deux + $un;
	}
	if($vpn_connexion->{domain} eq 'tunnel_deux')
	{
		#Récupération nombre connectés tunnel deux
		$vpn_un = $vpn_un + $un;
	}
		
	if($vpn_connexion->{domain} eq 'tunnel_trois')
	{
		#Récupération nombre connectés tunnel trois
		$vpn_trois = $vpn_trois + $un;	
	}		
}


print "vpn_deux:$vpn_deux vpn_un:$vpn_un vpn_trois:$vpn_trois";
#============================================
#FIN Récupération du nombre de connexion VPN
#============================================
