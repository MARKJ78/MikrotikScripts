:local checkDNS do={
	########################################## Enter URL's Here
	:local weburl [:toarray value="eu.wifiportal.io, bbc.co.uk,itv.co.uk,movenpick.com,galaxy.execloud.net,mbr.co.uk,live.com,microsoft.com,airangel.com,apple.com,samsung.com,bmw.com,ford.com,sony.com,facebook.com,twitter.com,instagram.com"];
	########################################## Enter URL's Here
	:local i 0;
	:local results {""};
	:local thisMany [:len $weburl];
	########################################## Remote Tests
	:put "###### Getting remote DNS servers for performance testing ######";
	:local dnsServers [/ ip dns get servers];
	:put "###### OKAY, Lets go...";
	:foreach svr in=$dnsServers do={
		:local retry 0;
		:local result {""};
		:set i ($i + 1);
		:put [:ip dns cache flush];
		:put "###### Test #$i. Testing directly with $svr ######";
		:local startTime [/system clock get time];
		:put "Start time: $startTime";
		###################################### Remote Resolver
	    :foreach element in=$weburl do={
			:put "Trying $element";
			:do { :set result [resolve $element server $svr];} on-error={ 
				:put "###### DNS Timeout.... Trying once more before aborting test"; :do {
					:set result [resolve $element server $svr];;
					:set retry ($retry + 1);
				};
			};
			:put "Success $result";
	    };

		##################################### Time formatting
		:local sum 0;
		:local endTime [/system clock get time];
		:local finalTime ( $endTime - $startTime );
		:set sum ( $sum + ( [ :pick $finalTime 0 2 ] * 60 * 60 ));
		:set sum ( $sum + ( [ :pick $finalTime 3 5 ] * 60 ));
		:set sum ( $sum + [ :pick $finalTime 6 8 ] );
		#################################### Time formatting
		:put "End time: $endTime";
		#################################### Remote Results
		:local overRun 0;
		:set overRun ($sum - 1);
		:local underRun 0;
		:set underRun (1 - $sum);
		  if ($sum <= 1) do={
		    :local result "###### Test #$i OO-PASSED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr";
		   	:set ($results->i) $result;
		  };
		    if ($sum > 1) do={
		    :local result "###### Test #$i XX-FAILED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr - That is $overRun more than it should be.";
		    :set ($results->i) $result;
		  };
		  #################################### Remote Results
	};
		    ######################################Check for Dynamic Servers
	    :local dnsServers [/ ip dns get dynamic-servers];
	    :foreach svr in=$dnsServers do={
		:local retry 0;
		:local result {""};
		:set i ($i + 1);
		:put [:ip dns cache flush];
		:put "###### Test #$i. Testing directly with $svr ######";
		:local startTime [/system clock get time];
		:put "Start time: $startTime";
		##################################### Remote Resolver
	    :foreach element in=$weburl do={
			:put "Trying $element";
			:do { :set result [resolve $element server $svr];} on-error={ 
				:put "###### DNS Timeout.... Trying once more before aborting test"; :do {
					:set result [resolve $element server $svr];;
					:set retry ($retry + 1);
				};
			};
			:put "Success $result";
	    };
	    ##################################### Remote Resolver
	    #####################################Check for Dynamic Servers
		##################################### Time formatting
		:local sum 0;
		:local endTime [/system clock get time];
		:local finalTime ( $endTime - $startTime );
		:set sum ( $sum + ( [ :pick $finalTime 0 2 ] * 60 * 60 ));
		:set sum ( $sum + ( [ :pick $finalTime 3 5 ] * 60 ));
		:set sum ( $sum + [ :pick $finalTime 6 8 ] );
		#################################### Time formatting
		:put "End time: $endTime";
		#################################### Dynamic Results
		:local overRun 0;
		:set overRun ($sum - 1);
		:local underRun 0;
		:set underRun (1 - $sum);
		  if ($sum <= 1) do={
		    :local result "###### Test #$i OO-PASSED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr";
		   	:set ($results->i) $result;
		  };
		    if ($sum > 1) do={
		    :local result "###### Test #$i XX-FAILED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr - That is $overRun more than it should be.";
		    :set ($results->i) $result;
		  };
		  #################################### Dynamic Results
	};
	####################################### Remote Tests
	####################################### Local Tests
	:local tests { 1="local server un-cached" ; 2="local server cached" };
	:foreach test in=$tests do={
		:local retry 0;
		:local result {""};
		:set i ($i + 1);
		:put "###### Test #$i. Testing with $test ######";
		if ($test="local server un-cached") do={
	    			:put "###### Flushing current cache"; 
					:put [:ip dns cache flush];
					/delay 2;
					:put "###### Flush Complete";
					:put "###### OKAY, Lets go...";
		    	};
		:local startTime [/system clock get time];
		:put "Start time: $startTime";
		##################################### Local Resolver
	    :foreach element in=$weburl do={
			:put "Trying $element";
			:do { :set result [:resolve $element];} on-error={ 
				:put "###### DNS Timeout.... Trying once more before aborting test"; :do {
					:set result [:resolve $element];
					:set retry ($retry + 1);
				};
			};
			:put "Success $result";
	    };
	    ##################################### Local Resolver
		##################################### Time formatting
		:local sum 0;
		:local endTime [/system clock get time];
		:local finalTime ( $endTime - $startTime );
		:set sum ( $sum + ( [ :pick $finalTime 0 2 ] * 60 * 60 ));
		:set sum ( $sum + ( [ :pick $finalTime 3 5 ] * 60 ));
		:set sum ( $sum + [ :pick $finalTime 6 8 ] );
		#################################### Time formatting
		:put "End time: $endTime";
		#################################### Local Results
		:local overRun 0;
		:set overRun ($sum - 1);
		:local underRun 0;
		:set underRun (1 - $sum);
		if ($sum <= 1) do={
		    :local result "###### Test #$i OO-PASSED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $test.";
		    :set ($results->i) $result;
		};
		if ($sum > 1) do={
		    :local result "###### Test #$i XX-FAILED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $test. That is $overRun more than it should be.";
		    set ($results->i) $result;
		};
		#################################### Local Results
	};
	###################################### Local Test
	###################################### Print Final Results
	:put "#############################################";
	:put "Each test should take <1s in a healthy system.";
	:put "There should be 0 retries.";
	:put "#############################################";
	:foreach i in=$results do={
		:put $i;
	};
	###################################### Print Final Results
};
$checkDNS;
