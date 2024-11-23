from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
import time

# start a new nmap scan on localhost with some specific options
def do_scan(targets, options):
        parsed = None
        nmproc = NmapProcess(targets, options)
        nmproc.run_background()
        while(float(nmproc.progress) < 100):
            print(f"current progress for {nmproc.targets}:{nmproc.progress}")
            time.sleep(2)
        try:
                parsed = NmapParser.parse(nmproc.stdout)
        except NmapParserException as e:
                print("Exception raised while parsing scan: {0}".format(e.msg))

        return parsed


# print scan results from a nmap report
def print_scan(nmap_report):
    print("Nmap {0}".format(
        nmap_report.version))

    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        print("Nmap scan report for {0} ({1})".format(
            tmp_host,
            host.address))
        print("Host is {0}.".format(host.status))
        print("  PORT     STATE         SERVICE")

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                    str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)
            print(pserv)
    print(nmap_report.summary)


if __name__ == "__main__":
    report = do_scan("10.11.114.0/24", "-sR")
    if report:
        print_scan(report)
    else:
        print("No results returned