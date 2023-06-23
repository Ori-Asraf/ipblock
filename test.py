import csv
import requests as rq
import json

path = 'list.csv'
apikey1 = ""
apikey2 = ""

def apiabuse_query(ip):
    url_abuse = 'https://api.abuseipdb.com/api/v2/check'
    query_abuse = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    header_abuse = {
        'Accept': 'application/json',
        'Key': f'{apikey1}'
    }
    respond_abuse = rq.request(method='GET', url=url_abuse, headers=header_abuse, params=query_abuse)
    retval = json.loads(respond_abuse.text)
    return retval


def apivoid_query(address):
    try:
        req = rq.get(url='https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/', params={
            "key": f"{apikey2}",
            "ip": f'{address}'
        })
        payload = json.loads(req.content.decode())

        return payload['data']
    except:
        return


def start():
    header_add = False
    with open(path, encoding='utf-8') as csv_file:
        src_ip = csv.DictReader(csv_file)
        for ip in src_ip:
            new_ip = str(ip['src'])
            new_count = str(ip['EventCount'])

            decode_abuse = apiabuse_query(new_ip)
            total_reports = decode_abuse['data']['totalReports']
            abuse_score = decode_abuse['data']['abuseConfidenceScore']
            numDistinctUsers = decode_abuse['data']['numDistinctUsers']
            domain = decode_abuse['data']['domain']
            countryCode = decode_abuse['data']['countryCode']

            data = apivoid_query(new_ip)

            if data:
                blacklist = data['report']['blacklists']['detections']

                with open('new_csv.csv', 'a') as new_file:
                    if not header_add:
                        fieldnames = ['numDistinctUsers', 'BlackLists', 'AbuseScore', 'totalReports', 'Domains',
                                      'IPAddress',
                                      'Count', 'Country Code']
                        csv_writer = csv.DictWriter(new_file, fieldnames=fieldnames)

                        csv_writer.writeheader()
                        header_add = True

                    new_file.write(
                        f'{numDistinctUsers},{blacklist},{abuse_score},{total_reports},{domain},{new_ip},{new_count},{countryCode} \n')

                print(f'Done with {new_ip}')

            else:
                print(f'Failed for {new_ip}')


start()
