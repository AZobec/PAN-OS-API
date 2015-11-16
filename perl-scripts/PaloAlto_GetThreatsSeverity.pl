#!/usr/bin/perl  
#===========================================
#Script GET THREATS SEVERITY PALOALTO
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
my $critical_counter = 0;
my $high_counter = 0;
my $medium_counter = 0;
my $low_counter = 0;
my $informational_counter = 0;
my $un = 1;
my $URL = 'https://'.$hostname.'/api/?type=report&reporttype=dynamic&reportname=custom-dynamic-report&cmd=<type><threat><aggregate-by><member>threatid</member><member>severity</member></aggregate-by><values><member>repeatcnt</member></values></threat></type><period>last-15-minutes</period><topn>10</topn><topm>10</topm><caption>Threat-Last-15Mn</caption>&key='.$httpskey.'';
my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });

#===========================================
#Récupération du nombre de Severity Threats
#===========================================

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

foreach my $threat_severity(@{ $doc->{response}->{report}->{result}->{entry}})
{
	if($threat_severity->{severity} eq 'informational')
	{
		#Récupération nombre de sévérités informational
		$informational_counter = $informational_counter + $threat_severity->{repeatcnt};
	}
	if($threat_severity->{severity} eq 'low')
	{
		#Récupération nombre de sévérités low
		$low_counter = $low_counter + $threat_severity->{repeatcnt};
	}
	if($threat_severity->{severity} eq 'medium')
	{
		#Récupération nombre de sévérités medium
		$medium_counter = $medium_counter + $threat_severity->{repeatcnt};
	}
	if($threat_severity->{severity} eq 'high')
	{
		#Récupération nombre de sévérités high
		$high_counter = $high_counter + $threat_severity->{repeatcnt};
	}
	if($threat_severity->{severity} eq 'critical')
	{
		#Récupération nombre de sévérités critical
		$critical_counter = $critical_counter + $threat_severity->{repeatcnt};
	}		
}


print "informational_counter:$informational_counter low_counter:$low_counter medium_counter:$medium_counter high_counter:$high_counter critical_counter:$critical_counter";
#==============================================
#FIN Récupération du nombre de Severity Threats
#==============================================
