from sslyze import (
    ServerScanRequest, 
    ServerNetworkLocation, 
    Scanner, 
    ServerScanStatusEnum, 
    ScanCommandAttemptStatusEnum, 
    ServerHostnameCouldNotBeResolved
)
from sslyze.mozilla_tls_profile.mozilla_config_checker import (
    MozillaTlsConfigurationChecker,
    ServerNotCompliantWithMozillaTlsConfiguration,
    MozillaTlsConfigurationEnum,
    ServerScanResultIncomplete,
)

from datetime import datetime
import re

class SSLScan:

    def __init__(self, hostname):
        self.scan_results = []
        
        all_scan_requests = []
        if isinstance(hostname, str):
            if ',' in hostname:
                hostnames = hostname.split(',')
            else:
                hostnames = [hostname]
            try:
                for host in hostnames:
                    all_scan_requests.append(
                        ServerScanRequest(server_location=ServerNetworkLocation(hostname=host))
                    )
            except ServerHostnameCouldNotBeResolved:
            # Handle bad input ie. invalid hostnames
                self.scan_results = [{'error':{'code':'01', 'message':'Could not resolve hosts!'}}]
                return
        scanner = Scanner()
        scanner.queue_scans(all_scan_requests)

        for result in scanner.get_results():
            server_object = {}
            server_object['hostname'] = result.server_location.hostname
            server_object['ip_address'] = result.server_location.ip_address
            if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                server_object['error'] = {'code': '02', 'message': 'Server could not be contacted!'}
                continue
            #Get supported tls versions
            supported_tls = []
            if result.scan_result.ssl_2_0_cipher_suites.result.is_tls_version_supported:
                supported_tls.append("SSLv2")
            if result.scan_result.ssl_3_0_cipher_suites.result.is_tls_version_supported:
                supported_tls.append("SSLv3")
            if result.scan_result.tls_1_0_cipher_suites.result.is_tls_version_supported:
                supported_tls.append("TLSv1.0")
            if result.scan_result.tls_1_1_cipher_suites.result.is_tls_version_supported:
                supported_tls.append("TLSv1.1")
            if result.scan_result.tls_1_2_cipher_suites.result.is_tls_version_supported:
                supported_tls.append("TLSv1.2")
            if result.scan_result.tls_1_3_cipher_suites.result.is_tls_version_supported:
                supported_tls.append("TLSv1.3")
            server_object['supported_tls'] = supported_tls
            #Get accepted ciphers
            server_object['supported_ciphers'] = []
            for tls in supported_tls:
                if tls == 'SSLv2':
                    cipher_command = result.scan_result.ssl_2_0_cipher_suites.result
                if tls == 'SSLv3':
                    cipher_command = result.scan_result.ssl_3_0_cipher_suites.result
                if tls == 'TLSv1.0':
                    cipher_command = result.scan_result.tls_1_0_cipher_suites.result
                if tls == 'TLSv1.1':
                    cipher_command = result.scan_result.tls_1_1_cipher_suites.result
                if tls == 'TLSv1.2':
                    cipher_command = result.scan_result.tls_1_2_cipher_suites.result
                if tls == 'TLSv1.3':
                    cipher_command = result.scan_result.tls_1_3_cipher_suites.result
                supported_ciphers = []
                for cipher in cipher_command.accepted_cipher_suites:
                    cipher_dict = {}
                    cipher_dict['name'] = cipher.cipher_suite.name
                    cipher_dict['key_size'] = cipher.cipher_suite.key_size
                    if cipher.ephemeral_key != None:
                        cipher_dict['ephemeral_type'] = cipher.ephemeral_key.type_name
                        cipher_dict['ephemeral_size'] = cipher.ephemeral_key.size
                        try:
                            cipher_dict['ephemeral_curve_name'] = cipher.ephemeral_key.curve_name
                        except:
                            cipher_dict['ephemeral_curve_name'] = None
                    supported_ciphers.append(cipher_dict)
                server_object['supported_ciphers'].append({str(tls):supported_ciphers})

            #Get certificate info
            if result.scan_result.certificate_info.status == ScanCommandAttemptStatusEnum.COMPLETED:
                server_object['certificate'] = [
                    {
                        'key_type': x.received_certificate_chain[0].public_key().__class__.__name__[1:] if x.received_certificate_chain[0].public_key() else None,
                        'subject':x.received_certificate_chain[0].subject.rfc4514_string(),
                        'serial':x.received_certificate_chain[0].serial_number,
                        'issuer':x.received_certificate_chain[0].issuer.rfc4514_string(),
                        'has_anchor':x.received_chain_contains_anchor_certificate,
                        #'hostname_validation':x.leaf_certificate_subject_matches_hostname,
                        'sha1_signature':x.verified_chain_has_sha1_signature,
                        'has_valid_order':x.received_chain_has_valid_order,
                        'hash_algorithm':x.received_certificate_chain[0].signature_hash_algorithm.name,
                        'ocsp_trusted':x.ocsp_response_is_trusted,
                        'ocsp_status':x.ocsp_response.certificate_status.name if x.ocsp_response != None else None,
                        #'received_chain':[ dict(z.split('=') for z in y.subject.rfc4514_string().split(',')) for y in x.received_certificate_chain] if x.received_certificate_chain != None else None,
                        'received_chain':[ dict(re.findall(r'(CN)=([a-zA-Z0-9*. ]+)', y.subject.rfc4514_string())) for y in x.received_certificate_chain] if x.received_certificate_chain != None else None,
                        #'verified_chain':[ dict(z.split('=') for z in y.subject.rfc4514_string().split(',')) for y in x.verified_certificate_chain] if x.verified_certificate_chain != None else None,
                        'verified_chain':[ dict(re.findall(r'(CN)=([a-zA-Z0-9*. ]+)', y.subject.rfc4514_string())) for y in x.verified_certificate_chain] if x.verified_certificate_chain != None else None,
                        'not_valid_before':x.received_certificate_chain[0].not_valid_before.strftime('%Y/%m/%d'),
                        'not_valid_after':x.received_certificate_chain[0].not_valid_after.strftime('%Y/%m/%d'),
                        'san':[ [z.value for z in y.value._general_names] for y in x.received_certificate_chain[0].extensions if y.oid._name == 'subjectAltName'],
                    }
                    for x in result.scan_result.certificate_info.result.certificate_deployments
                ]
                server_object['trusted_certificate'] = [
                        {
                            'subject':x.received_certificate_chain[1].subject.rfc4514_string() if len(x.received_certificate_chain) > 1 else x.received_certificate_chain[0].subject.rfc4514_string(),
                            'issuer':x.received_certificate_chain[1].issuer.rfc4514_string() if len(x.received_certificate_chain) > 1 else x.received_certificate_chain[0].issuer.rfc4514_string(),
                            'not_valid_before':x.received_certificate_chain[1].not_valid_before.strftime('%Y/%m/%d') if len(x.received_certificate_chain) > 1 else x.received_certificate_chain[0].not_valid_before.strftime('%Y/%m/%d'),
                            'not_valid_after':x.received_certificate_chain[1].not_valid_after.strftime('%Y/%m/%d') if len(x.received_certificate_chain) > 1 else x.received_certificate_chain[0].not_valid_after.strftime('%Y/%m/%d'),
                            #'trust_stores':[{'name': y.trust_store.name, 'error':y.openssl_error_string} for y in x.path_validation_results],
                        }
                        for x in result.scan_result.certificate_info.result.certificate_deployments
                    ]
            #Get SSL vulnerabilities
            if result.scan_result.elliptic_curves.status == ScanCommandAttemptStatusEnum.COMPLETED:
                server_object['ecdh_kex_support'] = result.scan_result.elliptic_curves.result.supports_ecdh_key_exchange
                server_object['ecdsa_supported_curves'] = [ x.name for x in result.scan_result.elliptic_curves.result.supported_curves ]
            if result.scan_result.session_renegotiation.status == ScanCommandAttemptStatusEnum.COMPLETED:
                server_object['session_renegiotiation_support'] = result.scan_result.session_renegotiation.result.supports_secure_renegotiation
                server_object['client_renegotiation_vulnerability'] = result.scan_result.session_renegotiation.result.is_vulnerable_to_client_renegotiation_dos
            if result.scan_result.robot.status == ScanCommandAttemptStatusEnum.COMPLETED:
                server_object['robot_vulnerability'] = result.scan_result.robot.result.robot_result.value
            if result.scan_result.heartbleed.status == ScanCommandAttemptStatusEnum.COMPLETED:
                server_object['heartbleed_vulnerability'] = result.scan_result.heartbleed.result.is_vulnerable_to_heartbleed
            if result.scan_result.session_resumption.status == ScanCommandAttemptStatusEnum.COMPLETED:
                server_object['session_resumption'] = result.scan_result.session_resumption.result.session_id_resumption_result.value
                server_object['tls_ticket_resumption'] = result.scan_result.session_resumption.result.tls_ticket_resumption_result.value
            if result.scan_result.openssl_ccs_injection.status == ScanCommandAttemptStatusEnum.COMPLETED:
                server_object['openssl_ccs_injection'] = result.scan_result.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection
            if result.scan_result.tls_compression.status == ScanCommandAttemptStatusEnum.COMPLETED:
                server_object['tls_compression'] = result.scan_result.tls_compression.result.supports_compression
            if result.scan_result.tls_1_3_early_data.status == ScanCommandAttemptStatusEnum.COMPLETED:
                server_object['tls_early'] = result.scan_result.tls_1_3_early_data.result.supports_early_data
            if result.scan_result.tls_fallback_scsv.status == ScanCommandAttemptStatusEnum.COMPLETED:
                server_object['tls_scsv_fallback'] = result.scan_result.tls_fallback_scsv.result.supports_fallback_scsv
            if result.scan_result.http_headers.status == ScanCommandAttemptStatusEnum.COMPLETED:
                if result.scan_result.http_headers.result.strict_transport_security_header:
                    server_object['hsts_support'] = {
                        'include_subdomain': result.scan_result.http_headers.result.strict_transport_security_header.include_subdomains,
                        'max_age': result.scan_result.http_headers.result.strict_transport_security_header.max_age,
                        'preload': result.scan_result.http_headers.result.strict_transport_security_header.preload,
                        }
            #Compare Mozilla scan
            mozilla_checker = MozillaTlsConfigurationChecker.get_default()
            try:
                mozilla_checker.check_server(against_config=MozillaTlsConfigurationEnum.INTERMEDIATE, server_scan_result=result)
                server_object['mozilla_checker'] = "Compliant"
            except ServerNotCompliantWithMozillaTlsConfiguration as e:
                are_all_servers_compliant = False
                server_object['mozilla_checker'] = "Not Compliant"
                mozilla_errors = []
                for criteria, error_desc in e.issues.items():
                    mozilla_errors.append({'criteria': criteria, 'error_desc': error_desc})
                server_object['mozilla_errors'] = mozilla_errors
            
            self.scan_results.append(server_object)
