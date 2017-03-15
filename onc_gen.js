var ca_id = guid();
	var config_id = guid();
	var client_id = guid();
	var result = "";
	
	function init(){
		$('#verifyX509').change(function(){
			if($(this).is(':checked')){
				$('#x509verification').show();
			}else{
				$('#x509verification').hide();
			}
		});
		$('#enableTLS').change(function(){
			if($(this).is(':checked')){
				$('#tlsbody').show();
			}else{
				$('#tlsbody').hide();
			}
		});
		$('#clienttype').change(function(){
			if($(this).val() === 'Ref'){
				$('#clientcert').show();
				$('#clientpattern').hide();
			}else if($(this).val() === 'Pattern'){
				$('#clientcert').hide();
				$('#clientpattern').show();
			}else{
				$('#clientcert').hide();
				$('#clientpattern').hide();
			}
		});
		$('#enableIssuer').change(function(){
			if($(this).is(':checked')){
				$('#issuerbody').show();
			}else{
				$('#issuerbody').hide();
			}
		});
	}
	
	$(init);
	
	function get_required(id){
		var value = $('#' + id).val();
		if(!value){
			$('#' + id).toggleClass('required', true);
		}else{
			$('#' + id).toggleClass('required', false);
		}
		return value;
	}
	
	function check_all(enforce_check, ids){
		if(enforce_check){
			$.each(ids, function(idx, id){
				var value = $('#' + id).val();
				if(value){
					$('#' + id).toggleClass('required', false);
				}else{
					$('#' + id).toggleClass('required', true);
				}
			});
		}else{
			$.each(ids, function(idx, id){
				$('#' + id).toggleClass('required', false);
			});
		}
	}
	
	function check_any(enforce_check, ids){
		var vals = [];
		var required_state = false;
		if(enforce_check){
			$.each(ids, function(idx, id){
				var value = $('#' + id).val();
				if(value){
					vals.push(value);
				}
			});
			required_state = true;
			console.log(ids);
			console.log(vals);
			if(vals.length > 0){
				required_state = false;
			}
		}
		$.each(ids, function(idx, id){
			$('#' + id).toggleClass('required', required_state);
		});
	}
	
	function set_error(msg){
		$('#error').html(msg);
		$('#error').show();
	}
	
	function clear_error(){
		$('#error').html('');
		$('#error').hide();
	}
	
	function checkFields() {
		var name = get_required('name');
		var hostname = get_required('hostname');
		var port = get_required('port');
		var username = get_required('username');
		var cipher  = $('#cipher').val();
		var auth = $('#auth').val();
		var auth_no_cache = $('#authnocache').val();
		var protocol = $('#protocol').val();
		var comp_lzo = $('#complzo').val();
		var comp_no_adapt = $('#compnoadapt').val();
		var save_creds = $('#savecreds').val();
		var auth_retry = $('#authrety').val();
		var ns_cert_type = $('#nscerttype').val();
		var push_peer_info = $('#pushpeerinfo').val();
		var reneg_sec = $('#renegsec').val();
		var server_poll_timeout = $('#serverpolltimeout').val();
		var shaper = $('#shaper').val();
		var static_challenge = $('#staticchallenge').val();
		var user_auth_type = $('#userauthtype').val();
		var ignore_default_route = $('#ignoredefaultroute').val();
		var verb = $('verb').val();
		var x509 = get_required('X509');
		
		if(!name || !hostname || !port || !username || !x509){
			set_error('Required fields missing.');
			return;
		}
		
		var verify_x509 = $('#verifyX509').is(':checked');
		var verify_x509_name = $('#X509name').val();
		var verify_x509_type = $('#X509type').val();
		var hash = $('#hash').val();
		
		check_all(verify_x509, ['X509name', 'X509type']);
		if(verify_x509 && (!verify_x509_name || !verify_x509_type)){
			set_error('Required fields missing.');
			return;
		}
		
		var tls_enabled = $('#enableTLS').is(':checked');
		var tls = $('#TLS').val()
		var key_direction = $('#keydirection').val();
		var remote_cert_tls = $('#remotecerttls').val();
		var remote_cert_eku = $('#remotecerteku').val();
		var tls_remote = $('#tlsremote').val();
		
		check_any(tls_enabled, ['TLS']);
		if(tls_enabled && !tls){
			set_error('Required fields missing.');
			return;
		}
		
		var client_type = $('#clienttype').val();
		
		var pkcs12 = $('#PKCS12').val();
		
		var client_ref_enabled = (client_type === 'Ref');
		check_any(client_ref_enabled, ['PKCS12']);
		if(client_ref_enabled && !pkcs12){
			set_error('Required fields missing.');
			return;
		}
		
		var issuer_ca_ref = $('#issuercaref').val();
		var issuer_enabled = $('#enableIssuer').is(':checked');
		var issuer_common_name = $('#commonname').val();
		var issuer_locality = $('#locality').val();
		var issuer_organization = $('#organization').val();
		var issuer_organizational_unit = $('#organizationalunit').val();
		var enrollment_uri = $('#enrollmenturi').val();
		
		var client_pattern_enabled = (client_type === 'Pattern');
		check_any(client_pattern_enabled && issuer_enabled, ['commonname', 'locality', 'organization', 'organizationalunit', 'enrollmenturi']);
		$('#clientpattern').toggleClass('required', false);
		console.log(issuer_ca_ref);
		if(client_pattern_enabled){
			if(issuer_enabled && !(issuer_common_name || issuer_locality || issuer_organization || issuer_organizational_unit || enrollment_uri)){
				set_error('Must specify at least one issuer field!');
				return;
			}
			if(!(issuer_enabled || issuer_ca_ref)){
				$('#clientpattern').toggleClass('required', true);
				set_error('Must specify issuer ca ref or filter!');
				return;
			}
		}
		
		var onc_config = create_base_config();
		onc_config.Certificates.push({
			"GUID": "{" + ca_id + "}",
			"Type": "Authority",
			"X509": formatValue(x509,'X509')
		});
		
		if(client_type === 'Ref'){
			onc_config.Certificates.push({
				"GUID": "{" + client_id + "}",
				"Type": "Client",
				"PKCS12": formatValue(pkcs12, 'PKCS12')
			});
		}
		
		clear_error();
		
		onc_config.NetworkConfigurations[0].Name = name;
		onc_config.NetworkConfigurations[0].VPN.Host = hostname;
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.AuthRetry = auth_retry;
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.Cipher = cipher;
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.Auth = auth;
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.UserAuthenticationType = user_auth_type;
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.AuthNoCache = toBoolean(auth_no_cache);
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.CompLZO = comp_lzo;
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.CompNoAdapt = toBoolean(comp_no_adapt);
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.SaveCredentials = toBoolean(save_creds);
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.AuthRetry = auth_retry;
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.Port = parseInt(port);
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.Proto = protocol;
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.NsCertType = ns_cert_type;
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.Username = username;
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.PushPeerInfo = toBoolean(push_peer_info);
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.IgnoreDefaultRoute = toBoolean(ignore_default_route);
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.Verb = verb;
		if(hash){
			onc_config.NetworkConfigurations[0].VPN.OpenVPN.VerifyHash = hash;
		}
		if(server_poll_timeout){
			onc_config.NetworkConfigurations[0].VPN.OpenVPN.ServerPollTimeout = parseInt(server_poll_timeout);
		}
		if(reneg_sec){
			onc_config.NetworkConfigurations[0].VPN.OpenVPN.RenegSec = parseInt(reneg_sec);
		}
		if(shaper){
			onc_config.NetworkConfigurations[0].VPN.OpenVPN.Shaper = parseInt(shaper);
		}
		if(static_challenge){
			onc_config.NetworkConfigurations[0].VPN.OpenVPN.StaticChallenge = static_challenge;
		}
		if(client_type === 'Pattern'){
			onc_config.NetworkConfigurations[0].VPN.OpenVPN.ClientCertPattern = {};
			if(issuer_ca_ref){
				onc_config.NetworkConfigurations[0].VPN.OpenVPN.ClientCertPattern.IssuerCARef =  [ "{" + ca_id + "}" ]
			}
			if(issuer_enabled){
				onc_config.NetworkConfigurations[0].VPN.OpenVPN.ClientCertPattern.Issuer = {}
				if(issuer_common_name){
					onc_config.NetworkConfigurations[0].VPN.OpenVPN.ClientCertPattern.Issuer.CommonName = issuer_common_name;
				}
				if(issuer_locality){
					onc_config.NetworkConfigurations[0].VPN.OpenVPN.ClientCertPattern.Issuer.Locality = issuer_locality;
				}
				if(issuer_organization){
					onc_config.NetworkConfigurations[0].VPN.OpenVPN.ClientCertPattern.Issuer.Organization = issuer_organization;
				}
				if(issuer_organizational_unit){
					onc_config.NetworkConfigurations[0].VPN.OpenVPN.ClientCertPattern.Issuer.OrganizationalUnit = issuer_organizational_unit;
				}
			}
			if(enrollment_uri){
				onc_config.NetworkConfigurations[0].VPN.OpenVPN.ClientCertPattern.EnrollMentURI = [enrollment_uri];
			}
		}
		
		onc_config.NetworkConfigurations[0].VPN.OpenVPN.ClientCertType = client_type;
		if(client_type === 'Ref'){
			onc_config.NetworkConfigurations[0].VPN.OpenVPN.ClientCertRef =  "{" + client_id + "}";
		}
		
		if(tls_enabled){
			onc_config.NetworkConfigurations[0].VPN.OpenVPN.TLSAuthContents = formatValue(tls,'TLS');
			onc_config.NetworkConfigurations[0].VPN.OpenVPN.KeyDirection = key_direction;
			onc_config.NetworkConfigurations[0].VPN.OpenVPN.RemoteCertTLS = remote_cert_tls;
			if(remote_cert_eku){
				onc_config.NetworkConfigurations[0].VPN.OpenVPN.RemoteCertEKU = remote_cert_eku;
			}
			if(tls_remote){
				onc_config.NetworkConfigurations[0].VPN.OpenVPN.TLSRemote = tls_remote;
			}
		}
		
		if(verify_x509){
			onc_config.NetworkConfigurations[0].VPN.OpenVPN.VerifyX509 = {
				"Name": verify_x509_name,
				"Type": verify_x509_type
			}
		}
		download(name+".onc", JSON.stringify(onc_config, null, '\t'));
	}
	
	
	function guid() {
	  function s4() {
	    return Math.floor((1 + Math.random()) * 0x10000)
	      .toString(16)
	      .substring(1);
	  }
	  return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
	    s4() + '-' + s4() + s4() + s4();
	}
	
	function toBoolean(value){
		return (value === "true");
	}

	function formatValue(value,type){

		if ((type === "X509") || (type === "PKCS12")) {
			var result = value.replace(/^.*#.*$\n/mg, "");
			result = result.replace(/^.*-.*$/mg, "");
			result = result.replace(/(\r\n|\n|\r)/gm,"");
			return result
		}else if (type === "TLS"){
			var result = value.replace(/^.*#.*$\n/mg, "");
			result = result.replace(/(?:\r\n|\r|\n)/g,"\n");
			return result			
		}
	}
	
	function create_base_config(){
		return {
			"Type": "UnencryptedConfiguration",
			"Certificates": [],
			"NetworkConfigurations": [{
				"GUID": "{" + config_id + "}",
				"Type": "VPN",
				"VPN": {
					"Type": "OpenVPN",
					"OpenVPN": {
						"ServerCARef": "{" + ca_id + "}",
					}
				}
			}]
		};
	}
	
	function download(filename, text) {
	    var pom = document.createElement('a');
	    pom.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
	    pom.setAttribute('download', filename);
	
	    if (document.createEvent) {
	        var event = document.createEvent('MouseEvents');
	        event.initEvent('click', true, true);
	        pom.dispatchEvent(event);
	    }
	    else {
	        pom.click();
	    }
	}