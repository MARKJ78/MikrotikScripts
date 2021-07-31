:local resolve do={
	########################################## Enter URL's Here
	:local weburl [:toarray value="bbc.co.uk,itv.co.uk,airangel.com,spotify.com,mbr.co.uk,netflix.com,live.com,amazon.com,microsoft.com,eu.wifiportal.io,airangel.com,apple.com,samsung.com,bmw.com,ford.com,sony.com,facebook.com,twitter.com,instagram.com"];
	########################################## Enter URL's Here
	:local thisMany [:len $weburl];
	:local resolvedAddress;
	:local retry 0;
	:put "###### Test #$i. Testing with $svr ######";
	:if ($flush) do={
		:put "Flushing local cache";
		/ip dns cache flush;
		/delay 2;
	};
	######################################### Resolver
	:put "OKAY.. lets go";
	:local startTime [/system clock get time];
	:put "Start time: $startTime";
	:foreach url in=$weburl do={
		:put "Trying $url";
		:if ($remoteSrv) do={
			:do {:set resolvedAddress [resolve $url server $svr];} on-error={
				:put "###### DNS Timeout for $url... Trying once more before aborting test"; 
				:do {
					:set resolvedAddress [resolve $url server $svr];
					:set retry ($retry + 1);
				};
			};
		} else={
			:do {:set resolvedAddress [resolve $url];} on-error={
				:put "###### DNS Timeout... Trying once more before aborting test"; 
				:do {
					:set resolvedAddress [resolve $url];
					:set retry ($retry + 1);
				};
			};
		};
	:put "Success $resolvedAddress";
	};
	##################################### Resolver End
	:local endTime [/system clock get time];
	:put "End time: $endTime";
	:put "";
	#################################### Format Results
	############takenFromWeb########### Time formatting
	:local sum 0;
	:local finalTime ( $endTime - $startTime );
	:set sum ( $sum + ( [ :pick $finalTime 0 2 ] * 60 * 60 ));
	:set sum ( $sum + ( [ :pick $finalTime 3 5 ] * 60 ));
	:set sum ( $sum + [ :pick $finalTime 6 8 ] );
	############takenFromWeb######## Time formatting End
	:local overRun ($sum - 2);
	:if ($sum <= 2) do={
		:local testResultPass "###### Test #$i OO-PASSED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr.";
		:set ($endResults->i) $testResultPass;
	} else={
		:local testResultFail "###### Test #$i XX-FAILED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr. That is $overRun more than it should be.";
		:set ($endResults->i) $testResultFail;
	};
	#################################### Format Results End
};
####################################### Resolve function end

# Start here

######################################### Define Servers and Test
:put "###### Getting remote DNS servers for performance testing ######";
:put "";
:local endResults {""};
:local manDnsServers [/ ip dns get servers];
:local dynDnsServers [/ ip dns get dynamic-servers];
:local dnsServers ($manDnsServers , $dynDnsServers , "the local server, un-cached" , "the local server, cached");
:local i 0; 
:local flush true;
:local remoteSrv false;
:local length [:len $dnsServers];
:local localTests ($length - 2); 
# ^ Ditinguishes DNS server as Mikrotik
:foreach svr in=$dnsServers do={
	:set flush true;
	:set remoteSrv false;
	# ^ Flag Resets
	:local position (:put [:find $dnsServers $svr]);
	:if ($position = $length -1) do={
		:set flush false;
	};
	# ^ Prevents cache flushing for last test (local MTK server cached)
	:if ($position < $localTests) do={
		:set remoteSrv true;
	};
	:set i ($i + 1);
	$resolve svr=$svr endResults=$endResults i=$i flush=$flush remoteSrv=$remoteSrv;
	# ^ Calls Resolver 
};
############################################## Define Servers and Test
###################################### Print Final Results to terminal
:put "";
:put "#################################################";
:put "# Each test should take < 2s in a healthy system.";
:put "# There should be 0 retries.";
:put "#################################################";
:foreach i in=$endResults do={
	:put $i;
};
:set endResults {","};
###################################### Print Final Results to terminal
