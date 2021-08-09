import re
from tplink import TippiLink
import sys

class Router:
    def __init__(self, iprt):
        macs = []

        host_bfl = ['192.168.66.4', '192.168.66.5', '192.168.66.23']
        host_tpl = ['192.168.66.32', '192.168.66.18']

        iprt = sys.argv[1]

        if iprt in host_bfl:
            user_name = os.getenv("BFL_ID")
            user_pasw = os.getenv("BFL_PW")
            macs.extend(scrap_bfl(x, user_name, user_pasw))

        elif iprt in host_tpl:
            user_name = os.getenv("TPLINK_ID")
            user_pasw = os.getenv("TPLINK_SECRET")
            tl = TippiLink(user_name, user_pasw, iprt)
            macs.extend([x[0] for x in tl.get_all_macs()])



        cnx = conexion()
        cursor = cnx.cursor()

        query = "select dir_mac from datos_red where fech_pag between subdate(curdate(), 30) and subdate(curdate(), -9999);"
        cursor.execute(query)

        i = []
        for x in cursor:
            i.append(x[0])

        jmacs = ' '.join(i)

        cursor.close()
        cnx.close()

        conx_macs = [x for x in macs if not in jmacs]

        ips_activas = []
        for mac in conx_macs:
            query1 = "select dir_ip from datos_red where dir_mac={}".format()
            cursor.execute(query1)
            record = cursor.fetchone()
            ips_activas.append(record[0])

        self.ips_router = ips_activas
