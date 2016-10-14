import json
import requests
import argparse
from highcharts import Highchart

parser = argparse.ArgumentParser()
parser.add_argument('-t', action='store', dest='token', help='Enter API token')
parser.add_argument('-k', action='store', dest='key', help='Enter API key')

args = parser.parse_args()
token = args.token
key = args.key

def topTenServers(token, key):
	getServers = requests.get('https://ws.riskiq.net/v1/inventory/facets/webComponentServer', auth=(token, key))
	servers = getServers.json()

	chartName = 'Top 10 Vulnerable Servers'
	chartData = {}
	n = 0

	for i in servers['facetValue']:
		if 'Apache' in i['term'] and 'Apache 2.4.20' not in i['term'] and 'Apache 2.4.10' not in i['term'] and 'Apache 2.4.12' not in i['term'] and 'Apache 2.4.16' not in i['term'] and 'Apache 2.2.29' not in i['term'] and 'Apache 2.2.31' not in i['term'] and 'Apache' != i['term'] or 'Microsoft-IIS 6.0' == i['term'] or 'Microsoft-IIS 5.0' == i['term'] == 'Microsoft-IIS' == i['term'] or 'Microsoft-IIS 4.0' == i['term']:

			data = {'y': i['count'], 'name': i['term']}
			chartData[n] = data
			n += 1

	topTenServers = {k: chartData[k] for k in chartData.keys()[:10]}

	H = Highchart(width=600, height=400)

	options = {
			'chart': {
	            'plotBackgroundColor': None,
	            'plotBorderWidth': None,
	            'plotShadow': False,
	            'spacingRight': 0
	        },
	        'title': {
	            'text': 'Top 10 Vulnerable Servers',
	            'align': 'left'
	        },
	        'legend':{
	            'align': 'right',
	            'verticalAlign': 'middle',
	            'layout': 'vertical'     
	        },
	        'tooltip': {
	            'pointFormat': '{series.name}: <b>{point.percentage:.1f}%</b>'
	        },
	    }

	H.set_dict_options(options)

	H.add_data_set(topTenServers.values(), 'pie', 'Servers', allowPointSelect=True,
	                cursor='pointer',
	                showInLegend=True,
	                dataLabels={
	                    'enabled': False,
	                    'format': '<b>{point.name}</b>: {point.percentage:.1f} %',
	                    'style': {
	                    'color': "(Highcharts.theme && Highcharts.theme.contrastTextColor) || 'black'"
	                    }
	                }
	            )

	H.htmlcontent
	H.save_file(chartName)
	print 'Exported file:', chartName

def topTenFrameworks(token,key):
    getFrameworks = requests.get('https://ws.riskiq.net/v1/inventory/facets/webComponentFramework', auth=(token, key))
    frameworks = getFrameworks.json()
    chartName = 'Top 10 Vulnerable Frameworks'
    chartData = {}
    n = 0

    for i in frameworks['facetValue']:
    	if 'PHP' in i['term'] and 'PHP 5.5' not in i['term'] and 'PHP 5.6' not in i['term'] and 'PHP 7' not in i['term'] or 'JBoss 3.2.7' in i['term'] or 'JBoss 5.0' in i['term'] or 'JBoss 4.0.5.GA' in i['term'] or 'JBoss 4.0.4.GA' in i['term'] or 'JBoss 4.2.3.GA' in i['term'] or 'JBoss 4.2.0.GA_CP05' in i['term'] or 'JBoss 4.3.0.GA_CP09' in i['term'] or 'JBoss 4.3.0.GA_CP06' in i['term'] or 'JBoss 4.2.0.GA_CP04' in i['term'] or 'JBoss 4.2.2.GA' in i['term'] or 'JBoss 4.2.0.GA' in i['term'] or 'JBoss 4.0.3SP1' in i['term'] or 'JBoss 4.3.0.GA' in i['term'] or 'JBoss 4.3.0.GA_CP07' in i['term'] or 'JBoss 4.2.1.GA' in i['term'] or 'JBoss 4.0.2' in i['term'] or 'JBoss 4.2.0.GA_CP07' in i['term'] or 'JBoss 4.3.0.GA_CP01' in i['term'] or 'JBoss 3.2.6' in i['term'] or 'JBoss 4.0.1' in i['term'] or 'JBoss 4.3.0.GA_CP02' in i['term'] or 'JBoss 4.2.0.GA_CP01' in i['term'] or 'JBoss 4.2.0.CR1' in i['term'] or 'JBoss @implementation.version@' in i['term'] or 'JBoss 4.3.0.GA_CP10' in i['term'] or 'JBossSecureServer' in i['term'] or 'JBoss 4.2.0.CR2' in i['term'] or 'SEEBURGER JBossAS' in i['term']:

    		data = {'y': i['count'], 'name': i['term']}
    		chartData[n] = data
    		n += 1

    topTenFrameworks = {k: chartData[k] for k in chartData.keys()[:10]}

    H = Highchart(width=600, height=400)

    options = {
    		'chart': {
                'plotBackgroundColor': None,
                'plotBorderWidth': None,
                'plotShadow': False,
                'spacingRight': 0
            },
            'title': {
                'text': 'Top 10 Vulnerable Frameworks',
                'align': 'left'
            },
            'legend':{
                'align': 'right',
                'verticalAlign': 'middle',
                'layout': 'vertical'     
            },
            'tooltip': {
                'pointFormat': '{series.name}: <b>{point.percentage:.1f}%</b>'
            },
        }

    H.set_dict_options(options)

    H.add_data_set(topTenFrameworks.values(), 'pie', 'Frameworks', allowPointSelect=True,
                    cursor='pointer',
                    showInLegend=True,
                    dataLabels={
                        'enabled': False,
                        'format': '<b>{point.name}</b>: {point.percentage:.1f} %',
                        'style': {
                        'color': "(Highcharts.theme && Highcharts.theme.contrastTextColor) || 'black'"
                        }
                    }
                )

    H.htmlcontent
    H.save_file(chartName)
    print 'Exported file:', chartName

def topTenCertIssuers(token,key):
    getCertIssuer = requests.get('https://ws.riskiq.net/v1/inventory/facets/issuerCommonName', auth=(token, key))
    issuer = getCertIssuer.json()
    chartName = 'Top 10 Certificate Issuers'
    chartData = {}
    n = 0

    for i in issuer['facetValue']:
    	data = {'y': i['count'], 'name': i['term']}
    	chartData[n] = data
    	n += 1

    topTen = {k: chartData[k] for k in chartData.keys()[:10]}

    H = Highchart(width=800, height=400)

    options = {
    		'chart': {
                'plotBackgroundColor': None,
                'plotBorderWidth': None,
                'plotShadow': False,
                'spacingRight': 0
            },
            'title': {
                'text': 'Top 10 Certificate Issuers',
                'align': 'left'
            },
            'legend':{
                'align': 'right',
                'verticalAlign': 'middle',
                'layout': 'vertical'     
            },
            'tooltip': {
                'pointFormat': '{series.name}: <b>{point.percentage:.1f}%</b>'
            },
        }

    H.set_dict_options(options)

    H.add_data_set(topTen.values(), 'pie', 'Frameworks', allowPointSelect=True,
                    cursor='pointer',
                    showInLegend=True,
                    dataLabels={
                        'enabled': False,
                        'format': '<b>{point.name}</b>: {point.percentage:.1f} %',
                        'style': {
                        'color': "(Highcharts.theme && Highcharts.theme.contrastTextColor) || 'black'"
                        }
                    }
                )

    H.htmlcontent
    H.save_file(chartName)
    print 'Exported file:', chartName

def certSigning(token,key):
    getCertSign = requests.get('https://ws.riskiq.net/v1/inventory/facets/sigAlgorithm', auth=(token, key))
    issuer = getCertSign.json()
    chartName = 'Certificate Signing'
    chartData = {}
    n = 0

    for i in issuer['facetValue']:
    	data = {'y': i['count'], 'name': i['term']}
    	chartData[n] = data
    	n += 1

    certSign = {k: chartData[k] for k in chartData.keys()[:10]}

    H = Highchart(width=600, height=400)

    options = {
    		'chart': {
                'plotBackgroundColor': None,
                'plotBorderWidth': None,
                'plotShadow': False,
                'spacingRight': 0
            },
            'title': {
                'text': 'Certificate Signing Algorithm',
                'align': 'left'
            },
            'legend':{
                'align': 'right',
                'verticalAlign': 'middle',
                'layout': 'vertical'     
            },
            'tooltip': {
                'pointFormat': '{series.name}: <b>{point.percentage:.1f}%</b>'
            },
        }

    H.set_dict_options(options)

    H.add_data_set(certSign.values(), 'pie', 'Frameworks', allowPointSelect=True,
                    cursor='pointer',
                    showInLegend=True,
                    dataLabels={
                        'enabled': False,
                        'format': '<b>{point.name}</b>: {point.percentage:.1f} %',
                        'style': {
                        'color': "(Highcharts.theme && Highcharts.theme.contrastTextColor) || 'black'"
                        }
                    }
                )

    H.htmlcontent
    H.save_file(chartName)
    print 'Exported file:', chartName

certSigning(token,key)
topTenCertIssuers(token,key)
topTenFrameworks(token, key)
topTenServers(token, key)










