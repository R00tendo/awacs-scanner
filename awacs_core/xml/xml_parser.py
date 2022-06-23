from xml.dom import minidom
import json


def parse(filename):
  pairs = []
  nmap_scan = minidom.parse(filename)
  ports = nmap_scan.getElementsByTagName('service')
  for port in ports:

    if port.hasAttribute('version') and port.hasAttribute('product'):
     pairs.append({'name':port.attributes['product'].value, 'version':port.attributes['version'].value})
     
  return pairs