"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import requests
import time
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('criminal-ip')


def make_api_call(method="GET", endpoint="", config=None, params=None, data=None, json_data=None):
    try:
        headers = {
            "x-api-key": config.get('api_key')
        }
        server_url = config.get('server_url').strip('/')
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = "https://" + server_url
        server_url = server_url + endpoint
        response = requests.request(method=method,
                                    url=server_url,
                                    headers=headers, data=data, json=json_data, params=params,
                                    verify=config.get('verify_ssl'))

        if response.ok and (response.json().get('status') not in [401, 413, 414, 415, 500, 403]):
            return response.json()
        else:
            if response.text != "":
                err_resp = response.json()
                failure_msg = err_resp['message']
                error_msg = 'Response [{0}: Details: {1}]'.format(err_resp.get('status'),
                                                                  failure_msg if failure_msg else '')
            else:
                error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
            logger.error(error_msg)
            raise ConnectorError(error_msg)
    except requests.exceptions.SSLError:
        logger.error('An SSL error occurred')
        raise ConnectorError('An SSL error occurred')
    except requests.exceptions.ConnectionError:
        logger.error('A connection error occurred')
        raise ConnectorError('A connection error occurred')
    except requests.exceptions.Timeout:
        logger.error('The request timed out')
        raise ConnectorError('The request timed out')
    except requests.exceptions.RequestException:
        logger.error('There was an error while handling the request')
        raise ConnectorError('There was an error while handling the request')
    except Exception as err:
        raise ConnectorError(str(err))


def get_domain_reputation(config, params):
    endpoint = "/v1/domain/scan"
    response = make_api_call(method='POST', endpoint=endpoint, data=params, config=config)
    data = response.get('data')
    retries = 0
    max_retries = 10
    retry_delay = 15
    while not data and retries < max_retries:
        if retries == 9:
            raise ConnectorError('Failed to get the data from Criminal IP')
        retries += 1
        time.sleep(retry_delay)
        response = make_api_call(method='POST', endpoint=endpoint, data=params, config=config)
        data = response.get('data')
    scan_id = response.get('data').get('scan_id')
    get_scan_status(scan_id, config)
    return make_api_call(method='GET', endpoint=f'/v2/domain/report/{scan_id}', data=params, config=config)


def get_scan_status(scan_id, config):
    retries = 0
    max_retries = 10
    retry_delay = 15
    endpoint = f"/v1/domain/status/{scan_id}"
    time.sleep(15)
    response = make_api_call(method='GET', endpoint=endpoint, config=config)
    scan_percentage = response.get('data', {}).get('scan_percentage')
    if scan_percentage == -1:
        raise ConnectorError('A connection error occurred')
    if scan_percentage == -2:
        raise ConnectorError('Domain does not exist')
    while scan_percentage != 100 and retries < max_retries:
        if retries == 9:
            raise ConnectorError('Failed to get the data from Criminal IP')
        retries += 1
        time.sleep(retry_delay)
        response = make_api_call(method='GET', endpoint=endpoint, config=config)
        scan_percentage = response.get('data', {}).get('scan_percentage')


def asset_search(config, params):
    """
    Search for assets in Criminal IP database
    """
    endpoint = "/v1/asset/search"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def attacker_analysis_report(config, params):
    """
    Get attacker analysis report
    """
    endpoint = "/v1/attacker/analysis/report"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def data_download(config, params):
    """
    Download data from Criminal IP
    """
    endpoint = "/v1/data/download"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def domain_private_full_scan(config, params):
    """
    Perform a private full scan on a domain
    """
    endpoint = "/v1/domain/private/full/scan"
    response = make_api_call(method='POST', endpoint=endpoint, data=params, config=config)
    data = response.get('data')
    retries = 0
    max_retries = 10
    retry_delay = 15
    while not data and retries < max_retries:
        if retries == 9:
            raise ConnectorError('Failed to get the data from Criminal IP')
        retries += 1
        time.sleep(retry_delay)
        response = make_api_call(method='POST', endpoint=endpoint, data=params, config=config)
        data = response.get('data')
    scan_id = response.get('data').get('scan_id')
    get_scan_status(scan_id, config)
    return make_api_call(method='GET', endpoint=f'/v2/domain/report/{scan_id}', data=params, config=config)


def domain_search(config, params):
    """
    Search for domains in Criminal IP database
    """
    endpoint = "/v1/domain/search"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def exploit_search(config, params):
    """
    Search for exploits in Criminal IP database
    """
    endpoint = "/v1/exploit/search"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def get_domain_reports(config, params):
    """
    Get domain reports from Criminal IP
    """
    endpoint = "/v1/domain/reports"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def get_employee_identity_analysis(config, params):
    """
    Get employee identity analysis from Criminal IP
    """
    endpoint = "/v1/employee/identity/analysis"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def get_ip_malicious_info(config, params):
    """
    Get malicious information about an IP address
    """
    endpoint = "/v1/ip/malicious-info"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def get_ip_report(config, params):
    """
    Get detailed report about an IP address
    """
    endpoint = "/v1/asset/ip/report"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def get_ip_report_summary(config, params):
    """
    Get summary report about an IP address
    """
    endpoint = "/v1/asset/ip/report/summary"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def get_ip_summary(config, params):
    """
    Get summary information about an IP address
    """
    endpoint = "/v1/asset/ip/summary"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def get_ip_suspicious_info(config, params):
    """
    Get suspicious information about an IP address
    """
    endpoint = "/v2/feature/ip/suspicious-info"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def hacking_group_feature(config, params):
    """
    Get information about hacking group features
    """
    endpoint = "/v1/hacking/group/feature"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def hosting_ip_information(config, params):
    """
    Get hosting information about an IP address
    """
    endpoint = "/v1/ip/hosting"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def image_search(config, params):
    """
    Search for images in Criminal IP database
    """
    endpoint = "/v1/image/search"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def ip_asn_history(config, params):
    """
    Get ASN history for an IP address
    """
    # Updated endpoint based on API documentation
    endpoint = "/v1/asset/ip/report"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def is_safe_dns_server(config, params):
    """
    Check if a DNS server is safe
    """
    endpoint = "/v1/feature/ip/is_safe_dns_server"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def privacy_threat(config, params):
    """
    Get privacy threat information
    """
    endpoint = "/v1/feature/ip/privacy-threat"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def real_ip_detection(config, params):
    """
    Detect real IP address
    """
    # Updated endpoint based on API documentation
    endpoint = "/v1/asset/ip/report"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def scan_domain(config, params):
    """
    Scan a domain
    """
    endpoint = "/v1/domain/scan"
    response = make_api_call(method='POST', endpoint=endpoint, data=params, config=config)
    data = response.get('data')
    retries = 0
    max_retries = 10
    retry_delay = 15
    while not data and retries < max_retries:
        if retries == 9:
            raise ConnectorError('Failed to get the data from Criminal IP')
        retries += 1
        time.sleep(retry_delay)
        response = make_api_call(method='POST', endpoint=endpoint, data=params, config=config)
        data = response.get('data')
    scan_id = response.get('data').get('scan_id')
    get_scan_status(scan_id, config)
    return make_api_call(method='GET', endpoint=f'/v2/domain/report/{scan_id}', data=params, config=config)


def search_banners(config, params):
    """
    Search for banners in Criminal IP database
    """
    endpoint = "/v1/banner/search"
    # Ensure query parameter is present
    if 'query' not in params:
        params['query'] = 'ssh'  # Default query if none provided
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def search_vulnerability(config, params):
    """
    Search for vulnerabilities in Criminal IP database
    """
    endpoint = "/v1/vulnerability/search"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def url_lookups_scans(config, params):
    """
    Lookup and scan URLs
    """
    endpoint = "/v1/url/lookups/scans"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def vpn_ip_status(config, params):
    """
    Get VPN status of an IP address
    """
    endpoint = "/v1/ip/vpn"
    return make_api_call(method='GET', endpoint=endpoint, params=params, config=config)


def _check_health(config):
    try:
        endpoint = f"/v1/user/me"
        make_api_call(method='POST', endpoint=endpoint, config=config)
        return True
    except Exception as e:
        logger.error("Invalid Credentials: %s" % str(e))
        raise ConnectorError("Invalid Credentials")


operations = {
    'get_url_reputation': get_domain_reputation,
    'get_ip_reputation': get_domain_reputation,
    'get_domain_reputation': get_domain_reputation,
    'asset_search': asset_search,
    'attacker_analysis_report': attacker_analysis_report,
    'data_download': data_download,
    'domain_private_full_scan': domain_private_full_scan,
    'domain_search': domain_search,
    'exploit_search': exploit_search,
    'get_domain_reports': get_domain_reports,
    'get_employee_identity_analysis': get_employee_identity_analysis,
    'get_ip_malicious_info': get_ip_malicious_info,
    'get_ip_report': get_ip_report,
    'get_ip_report_summary': get_ip_report_summary,
    'get_ip_summary': get_ip_summary,
    'get_ip_suspicious_info': get_ip_suspicious_info,
    'hacking_group_feature': hacking_group_feature,
    'hosting_ip_information': hosting_ip_information,
    'image_search': image_search,
    'ip_asn_history': ip_asn_history,
    'is_safe_dns_server': is_safe_dns_server,
    'privacy_threat': privacy_threat,
    'real_ip_detection': real_ip_detection,
    'scan_domain': scan_domain,
    'search_banners': search_banners,
    'search_vulnerability': search_vulnerability,
    'url_lookups_scans': url_lookups_scans,
    'vpn_ip_status': vpn_ip_status
}
