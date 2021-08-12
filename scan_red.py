import os
import sys
import mysql.connector
from dotenv import load_dotenv
import pandas as pd
import numpy as np
import requests
import xmltodict
import re

dir_work = '/home/luis/cibercom'

sys.path.append(dir_work)

from tplink import TippiLink

load_dotenv(os.path.join(dir_work, '.env'))

def conexion():
    
    sql_id = os.getenv("SQL_ID")
    sql_pw = os.getenv("SQL_PW")
    sql_db = os.getenv("SQL_DB")
    cnx = mysql.connector.connect(user=sql_id, password=sql_pw, host='127.0.0.1', database=sql_db)
    return cnx

def extralias(l):
    cnx = conexion()
    cursor = cnx.cursor()
    
    query  = "select datos_per.coduser, datos_per.nom_apell, "
    query += "datos_red.dir_ip from datos_red, datos_per "
    query += "where datos_per.coduser=datos_red.coduser "
    query += "and datos_red.dir_ip='{}';".format(l)

    try:
        cursor.execute(query)
        record = cursor.fetchone()
        return record[1][:8]
        
    except:
        return l[-6:]


def learconx(ipserver, file='ips.txt'):
    url ='http://{}/{}'.format(ipserver, file)
    
    try:
        response = requests.get(url) #get data from json file located at specified URL 
    except:
        return 'Content was not found.'
    
    if response.status_code == requests.codes.ok:
        txtResponse = response.text  

        return txtResponse + ipserver[:11]+ipserver[11:].zfill(3)

    else:
        return 'Content was not found.'
    

def valip(ip):
    return ip.find('192.168.4')!=-1 or ip.find('192.168.35')!=-1


def learxml(url='192.168.35.69', path_file='diagnos.xml'):
    texto = learconx(url, path_file)

    inicio = texto.find('<routers>')
    fin = texto.find('</routers>')+len('</routers>')

    xml_data = texto[inicio:fin]

    my_dict = xmltodict.parse(xml_data)
    ipsr = [x['dirIp'] for x in my_dict['routers']['router'] if x['estado'] == 'ok']
    ipsr = [x[:11]+x[11:].zfill(3) for x in ipsr]
    
    return ipsr


def ipsactivos():
    ipx = []
    ipserv = ['192.168.35.69', '192.168.35.75']
    
    ipx = [learconx(x).split('\n') for x in ipserv]
    ipa = []

    for x in ipx:
        ipa += x
    
    ipa = [ix for ix in ipa if valip(ix)]
    ipa.extend(learxml()) # lee archivo xml actualizado por diagnos_ap.pl
    ipa = list(set(ipa))
    
    return ipa


def extrarnodos(path):
    dest = os.walk( path )

    nodos = [x for x in dest]
    fcosa = []

    for nodo in nodos:

        if len(nodo[2]) > 0:
            fcosa.append([nodo[0], nodo[2][0]])
    return fcosa


class Router:
    def __init__(self, iprt):
        macs = []

        host_bfl = ['192.168.66.4', '192.168.66.5', '192.168.66.23']
        host_tpl = ['192.168.66.32', '192.168.66.18']

        if iprt in host_bfl:
            user_name = os.getenv("BFL_ID")
            user_pasw = os.getenv("BFL_PW")
            macs.extend(self.scrap_bfl(iprt, user_name, user_pasw))

        elif iprt in host_tpl:
            user_name = os.getenv("TPLINK_ID")
            user_pasw = os.getenv("TPLINK_SECRET")
            tl = TippiLink(user_name, user_pasw, iprt)
            macs.extend([x[0] for x in tl.get_all_macs()])

        cnx = conexion()
        cursor = cnx.cursor()

        ips_activas = []
        for mac in macs:
            query = "select dir_ip from datos_red where dir_mac='{}'".format(mac)
            try:
                cursor.execute(query)
                record = cursor.fetchone()
                ips_activas.append(record[0])
            except:
                pass
    
        cursor.close()
        cnx.close()
        
        self.ips_router = ips_activas
        
    def elimrep(self, a):
        b = [a.count(x) for x in a]
        c = [x[0] for x in zip(a, b) if x[1] == 1]
        return c

    def scrap_bfl(self, bfl_hs, user_name, user_pasw):
        url ='http://{}/Status_Wireless.asp'.format(bfl_hs)

        try:
            r = requests.get(url, auth=(user_name, user_pasw))
            data = r.text
        except:
            data = ''

        p = re.compile(r'(?:[0-9a-fA-F]:?){12}')

        macs = []

        found = re.findall(p, data)
        for a in found:
            macs.append(a)

        # las repetidas son la mac del router
        macs = self.elimrep(macs)
        return macs

class Arbolito:
    
    def __init__(self, datos):
        
        caminos = datos.path
        
        caminos = list(set(caminos))

        maximo = 0
        separador ='/'

        temp = []
        for camino in caminos:
            temp.append(camino.split(separador))
            if len(camino.split(separador)) > maximo:
                maximo = len(camino.split(separador))
        caminos = temp.copy()

        alt_caminos = []
        for camino in caminos:
            temp = ''
            for nodo in camino:
                temp += nodo+separador
                alt_caminos.append(temp[:-(len(separador)+len(nodo))]+'**'+ nodo)

        alt_caminos = list(set(alt_caminos))

        for i in range(len(alt_caminos)):
            alt_caminos[i] = alt_caminos[i].split('**')
            alt_caminos[i] = {'direccion': alt_caminos[i][0], 'nombre': alt_caminos[i][1]}

        alt_caminos = np.array(alt_caminos)


        def __buscar_hijos(direccion, nombre):
            hijos = [x['nombre'] for x in alt_caminos if x['direccion']==direccion+nombre+separador]
            return hijos
        
        def __buscar_padre(direccion, nombre):
            dir_list = direccion.split(separador)
            posicion = -2 if len(dir_list)>1 else -1
            padre = dir_list[posicion] # penultimo porque ultimo siempre es vacio por contener separador al final
            return padre

        def __buscar_frutas(direccion, nombre):
            # frutas = list(datos[datos['path']==direccion+nombre]['archivo'].values)
            
            a = datos.loc[datos['path']==direccion+nombre, ['archivo','referidos']]
            frutas = []
            for index, row in a.iterrows():
                i_targets = row['referidos'].split('#')
                targets = [target.split('*') for target in i_targets if len(target)>0]
                source  = row['archivo']
                if len(targets)>0:
                    frutas.extend({'source':source, 'nexo': target[0], 'target': target[1]} for target in targets)
                else:
                    frutas.append({'source':source, 'nexo': 'default','target': nombre})
            return frutas
        
        
        def __numprgs(direccion, nombre):
            a = datos.loc[datos['path']==direccion+nombre]
            prgs   = list(datos[datos['path']==direccion+nombre]['archivo'].values)
            clases = []
            for programa in prgs:
                b = a.loc[a['archivo']==programa, 'grupo'].values[0]
                clases.append([programa, b])
            
            return clases
        

        def __buscar_nivel(direccion, nombre):
            dir_list = direccion.split(separador)
            return len(dir_list)


        def __ramas():
            
            ramas = []
            
            for camino in alt_caminos:
                parent = __buscar_padre(camino['direccion'], camino['nombre'])
                frutas = __buscar_frutas(camino['direccion'], camino['nombre'])
                progms = __numprgs(camino['direccion'], camino['nombre'])
                hijos  = __buscar_hijos(camino['direccion'], camino['nombre'])
                nivel  = __buscar_nivel(camino['direccion'], camino['nombre'])
                rama = {'parent': parent, 'name': camino['nombre'], 'frutas': frutas, 
                        'children': hijos, 'nivel': str(nivel), 'progms': progms}
                ramas.append(rama)
                
            return ramas    
                
        ramas = __ramas()
        self.ramas = ramas
        
        def __agrega_hijo(abuelo, padre):
            for rama in ramas:

                if rama['name'] == padre and rama['parent'] == abuelo:

                    dat_niv = {'name': str(rama['name']), 'parent': str(rama['parent']),
                               'frutas': rama['frutas'], 'nivel': rama['nivel'], 'progms': rama['progms']}
                    dat_niv['children'] = [__agrega_hijo(rama['name'], children) for children in rama['children']]

                    if dat_niv['children'] == [None] or dat_niv['children'] == [None, None]:
                        dat_niv.pop('children')

                    return dat_niv        
        
        def __crearbol():
            treeData = []
            
            for rama in ramas:
                if int(rama['nivel']) == 1:
                    dat_anid = {'name': rama['name'], 'parent': rama['parent'],
                                'frutas': rama['frutas'], 'nivel': rama['nivel'], 'progms': rama['progms']}
                    dat_anid['children'] = [__agrega_hijo(rama['name'], children) for children in rama['children']]
                    break                
            treeData.append(dat_anid)
            
            return treeData
        
        self.arbol = __crearbol()

directorios = extrarnodos(os.path.join(dir_work, 'arbol'))
clasificacion = []
activos = ipsactivos()

for directorio in directorios:

    estado = 0 # no activo
    referidos = '#'
    
    with open(os.path.join(directorio[0], directorio[1])) as f:
        f_line = f.readline().replace('\n', '')
        
        han = ['127.0.0.1'] # host activos en nodo
        while f_line:
            ip = f_line[:11]+f_line[11:].zfill(3)

            if ip in activos:
                estado = 1 # nodo activo

                if ip.find('192.168.66.') != -1:
                    # desplegar conex2xxx
                    rout = Router(f_line) # ip sin zfill
                    han.extend(rout.ips_router)
                else:
                    han.append(ip)
                    
            # leer siguiente ip del nodo
            f_line = f.readline().replace('\n', '')
                
        for ip in han:
            clasificacion.append({'path': directorio[0].replace('/home/luis/cibercom/arbol', 'cibercom'), 
                                  'archivo': extralias(ip), 'estado': estado, 
                                  'referidos': referidos, 'grupo': 0})


datos = pd.DataFrame(clasificacion)

a = Arbolito(datos)

treeData = 'var arbol = '+ str(a.arbol) + ';'

treeData = treeData.replace("{'source':", "{source:")
treeData = treeData.replace(" 'target':", " target:")
treeData = treeData.replace(" 'nexo':", " nexo:")

with open('/var/www/html/scan_red/arbol.js', 'w') as js_file:
    js_file.write(treeData)