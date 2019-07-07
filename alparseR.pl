#!/usr/bin/perl

use strict;
use warnings;
use DBI;
use POSIX qw(strftime);
use YAML qw(LoadFile Load);
use Date::Parse;

my ($user, $up, %alParse);
my ($dbn, $dsn, $dbh);

my $config = LoadFile('/root/inc/yaml/.db/dbi.yaml');

my $monstr      = strftime '%b', localtime;
my $driver	= 'mysql';
my $dbu         = $config->{user};
my $dbp         = $config->{pass};
my $err 	= $DBI::errstr;

open my $fh, '<', "/etc/trueuserdomains" or die "[!!] Cannot open file! $! \n";
chomp (my @users = <$fh>);
close $fh;

foreach (@users) {
	$user = $_;
	$user =~ s/^.+(?<=: )(.*)$/$1/;
	$up = "${user}";
	$up =~ s/(.{8}).*/$1/;
	
	$dbn 	= "${up}_alp${monstr};";
	$dsn 	= "DBI:$driver:";
	$dbh 	= DBI->connect($dsn, $dbu, $dbp) or die $err;
	
	main();
}

sub main {
	check_and_create_db();
	my $directory = "/etc/apache2/logs/domlogs/$user/";
	opendir ( DIR , $directory ) or die "[!!] Can't open $directory: $!";
	chomp ( my @files = grep { -f "$directory/$_"} readdir(DIR));
	closedir DIR;

	foreach my $file (@files) {
		create_table($file);		
		create_metas($file);
		open ( FILE, "< $directory/$file" ) or warn "[!!] Unable to access $file: $!";
		chomp ( my @entries = <FILE> );
		close(FILE);
		foreach my $row (@entries) {
			filter_entries($row);
			filter_dup_ins_ent($file);
		}
		update_metas($file);
	}
}

sub filter_entries {
	my %monum = qw(
        Jan 01  Feb 02  Mar 03  Apr 04 May 05 Jun 06
        Jul 07  Aug 08  Sep 09  Oct 10 Nov 11 Dec 12
	);
	foreach my $line (@_) {
		if ( $line =~ m|(^\S+)(?= -)| ) {
			%alParse = ( 'host' => $1 );
		}
		if ( $line =~ m|\[([\d]{2})/(.*)/([\d]{4}):([\d]{2}:[\d]{2}:[\d]{2}) |) {
			$alParse{'date'} = $3.'-'.$monum{$2}.'-'.$1.' '.$4;
		}		
		if ( $line =~ m|(?<=\] \")(\S+)(?= /)| ) {
			$alParse{'method'} = $1;
		}
		if ( $line =~ m|(?<= )(\S+)(?= HTTP)| ) {
			$alParse{'resource'} = $1;
		}
		if ( $line =~ m|(HTTP/[12]\.[10])(?=" \d)| ) {
			$alParse{'protocol'} = $1;
		}
		if ( $line =~ m|(?<=" )(\d{3})(?= [-\d])| ) {
			$alParse{'status'} = $1;
		}
		if ( $line =~ m|(?<= \d{3} )(\d+\|-)(?= ")|) {
			$alParse{'size'} = $1;
		}
		if ( $line =~ m|(?<=[-\d] ")([^"]+)| ) {
			$alParse{'referrer'} =  $1;
		}
		if ( $line =~ m|(?<=" ")(.*)(?="$)| ) {
			$alParse{'ua'} = $1;
		}
	}
}

sub check_and_create_db {
	my $sth = $dbh->prepare(
		"SHOW DATABASES LIKE '${up}_alp${monstr}';"
	);
	$sth->execute();
	my @dbFound = $sth->fetchrow_array();
	$sth->finish;
	
	if (!@dbFound) {
		my $dbCommand = `uapi --user=${user} Mysql create_database name='${up}_alp${monstr}' 2> /dev/null`;
		my $yaml = Load $dbCommand;
		my $status = $yaml->{result}->{status}; 
		my $apierr = $yaml->{result}->{errors}[0];	
	
		warn "[!!] $apierr\n" and last if ($status != 1);	
	}	
}

sub create_table {
	my $domain = $_[0];
	$domain =~ s/(\.|\-)/_/g;
	my $sth = $dbh->prepare(
		"CREATE TABLE IF NOT EXISTS ${up}_alp${monstr}.al_$domain (".
		"host varchar(50) COLLATE utf8mb4_unicode_ci,".
		"date datetime COLLATE utf8mb4_unicode_ci,".
		"method tinytext COLLATE utf8mb4_unicode_ci,".
		"resource varchar(100) COLLATE utf8mb4_unicode_ci,".
		"protocol varchar(10) COLLATE utf8mb4_unicode_ci,".
		"status_code int(3) COLLATE utf8mb4_unicode_ci,".
		"obj_size mediumint COLLATE utf8mb4_unicode_ci,".
		"referrer varchar(256) COLLATE utf8mb4_unicode_ci,".
		"user_agent varchar(256) COLLATE utf8mb4_unicode_ci".
		");"
	);
	$sth->execute();
	$sth->finish or die $err;
	print "Table al_$domain created for $_[0]\n";
}

sub filter_dup_ins_ent {
	my $domain = $_[0];
        $domain =~ s/(\.|\-)/_/g;
	
	my $sth = $dbh->prepare(
		"SELECT last_date ".
		"FROM ${up}_alp${monstr}.al_meta ".
		"WHERE log_name = 'al_$domain';"
	);
	$sth->execute() or die $err;
	my @last_date = $sth->fetchrow_array();
	my $last_parsed_epoc = str2time($last_date[0]);
	my $cur_entry_epoc = str2time($alParse{'date'});

	if ($last_parsed_epoc < $cur_entry_epoc) {
		insert_entries($_[0]);
	}
	
	$sth->finish();
}

sub insert_entries {
	my $domain = $_[0];
	$domain =~ s/(\.|\-)/_/g;
	
	my $sth = $dbh->prepare(
	        "INSERT INTO ${up}_alp${monstr}.al_$domain ".
	        "VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ? );"
	);
	$sth->execute(	
		$alParse{'host'}, $alParse{'date'}, $alParse{'method'}, 
		$alParse{'resource'}, $alParse{'protocol'}, $alParse{'status'},
		$alParse{'size'}, $alParse{'referrer'}, $alParse{'ua'}
	);
	$sth->finish or die $err;
}

sub create_metas {
        my $domain = $_[0];
        $domain =~ s/(\.|\-)/_/g;

        my $sth = $dbh->prepare(
                "CREATE TABLE IF NOT EXISTS ${up}_alp${monstr}.al_meta (".
		"log_name varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL UNIQUE,".
                "last_date datetime COLLATE utf8mb4_unicode_ci".
		");"
	);
	$sth->execute();
	$sth->finish or die $err;
	$sth = $dbh->prepare(
		"INSERT IGNORE INTO ${up}_alp${monstr}.al_meta ".
		"VALUES('al_$domain','1969-12-31 18:00:00');"
	);
	$sth->execute();
	$sth->finish or die $err;
}

sub update_metas {
        my $domain = $_[0];
        $domain =~ s/(\.|\-)/_/g;
	
	my $sth = $dbh->prepare(
		"UPDATE ${up}_alp${monstr}.al_meta ".
		"SET last_date='$alParse{date}' ".
		"WHERE log_name='al_$domain';"
	);
	$sth->execute();
	$sth->finish or die $err;
	$alParse{'date'} = '1969-12-31 18:00:00'
}
