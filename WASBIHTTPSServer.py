#!/usr/bin/env python3

"""Simple HTTPS Server With Upload.

This module builds on BaseHTTPServer by implementing the standard GET
and HEAD requests in a fairly straightforward manner.

"""

__version__ = "1.0"
__all__ = ["SimpleHTTPSRequestHandler"]
__author__ = "Edited version of bones7456 By 3CK0"
__home_page__ = "https://github.com/ECHO-3CK0/WASABIHTTPSServer"


import posixpath
import http.server
import urllib.request, urllib.parse, urllib.error
import html
import shutil
import mimetypes
import re
from io import BytesIO
from datetime import datetime, timedelta
import argparse
import os
import ssl
import textwrap
from socket import gethostname
import socketserver


class Bcolors:
    OK = '\033[92m'  # GREEN
    WARNING = '\033[93m'  # YELLOW
    FAIL = '\033[91m'  # RED
    BLUE = '\033[96m'
    RESET = '\033[0m'  # RESET COLOR
    BLINKING = '\033[6m '
    ITALIC = '\033[3m '
    STRIKE = '\033[9m '
    UNDERLINE = '\033[4m '

class Notification:
    OK = (f"{Bcolors.OK}[*] {Bcolors.RESET}")
    WARN = (f"{Bcolors.WARNING}[+] {Bcolors.RESET}")
    ERROR = (f"{Bcolors.FAIL}[-] {Bcolors.RESET}")
    R = [Bcolors.BLUE, Bcolors.WARNING, Bcolors.FAIL, Bcolors.OK, Bcolors.RESET ]

def banner():
    ver = "ver 1.0"
    tools = "HTTPSServer with upload"
    print(f"""

{Bcolors.WARNING}{"-" * 90}  
{Bcolors.FAIL}  
 \t ▄█     █▄     ▄████████    ▄████████    ▄████████ ▀█████████▄   ▄█  
\t███     ███   ███    ███   ███    ███   ███    ███   ███    ███ ███  
\t███     ███   ███    ███   ███    █▀    ███    ███   ███    ███ ███▌ 
\t███     ███   ███    ███   ███          ███    ███  ▄███▄▄▄██▀  ███▌ 
\t███     ███ ▀███████████ ▀███████████ ▀███████████ ▀▀███▀▀▀██▄  ███▌ 
\t███     ███   ███    ███          ███   ███    ███   ███    ██▄ ███  
\t███ ▄█▄ ███   ███    ███    ▄█    ███   ███    ███   ███    ███ ███  
\t ▀███▀███▀    ███    █▀   ▄████████▀    ███    █▀  ▄█████████▀  █▀   
{Bcolors.BLUE}              {tools}    {ver}      POWERED BY 3CK0\n{Bcolors.RESET}{Bcolors.ITALIC}
{Bcolors.FAIL}
            _   _ _____ _____ ____  ____ ____                           
           | | | |_   _|_   _|  _ \/ ___/ ___|  ___ _ ____   _____ _ __ 
           | |_| | | |   | | | |_) \___ \___ \ / _ \ '__\ \ / / _ \ '__|
           |  _  | | |   | | |  __/ ___) |__) |  __/ |   \ V /  __/ |   
           |_| |_| |_|   |_| |_|   |____/____/ \___|_|    \_/ \___|_|   
                                                                                                        
{Bcolors.RESET}  
""")

class SimpleHTTPSRequestHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTPS request handler with GET/HEAD/POST commands.

    This serves files from the current directory and any of its
    subdirectories.  The MIME type for files is determined by
    calling the .guess_type() method. And can reveive file uploaded
    by client.

    The GET/HEAD/POST requests are identical except that the HEAD
    request omits the actual contents of the file.

    """

    server_version = "SimpleHTTPSWithUpload/" + __version__
    download_path = ""          #Download path
    upload_path = ""            #Upload path



    def do_GET(self):
        """Serve a GET request."""
        f = self.send_head()
        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def do_HEAD(self):
        """Serve a HEAD request."""
        f = self.send_head()
        if f:
            f.close()

    def do_POST(self):
        """Serve a POST request."""
        r, info = self.deal_post_data()
        print((r, info, "by: ", self.client_address))
        f = BytesIO()
        f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write(b"<html>\n<title>Upload Result Page</title>\n")
        f.write(b"<body>\n<h2>Upload Result Page</h2>\n")
        f.write(b"<hr>\n")
        if r:
            f.write(b"<strong>Success:</strong>")
        else:
            f.write(b"<strong>Failed:</strong>")
        f.write(info.encode())
        f.write(("<br><a href=\"%s\">back</a>" % self.headers['referer']).encode())
        f.write(b"<hr><small>Powerd By: 3CK0, check new version at ")
        f.write(b"<a href=\"https://github.com/ECHO-3CK0/WASABIHTTPSServer\">")
        f.write(b"here</a>.</small></body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def deal_post_data(self):
        content_type = self.headers['content-type']
        if not content_type:
            return (False, "Content-Type header doesn't contain boundary")
        boundary = content_type.split("=")[1].encode()
        remainbytes = int(self.headers['content-length'])
        line = self.rfile.readline()
        remainbytes -= len(line)
        if not boundary in line:
            return (False, "Content NOT begin with boundary")
        line = self.rfile.readline()
        remainbytes -= len(line)
        fn = re.findall(r'Content-Disposition.*name="file"; filename="(.*)"', line.decode())
        if not fn:
            return (False, "Can't find out file name...")
        path = self.translate_upload_path()
        fn = os.path.join(path, fn[0])
        line = self.rfile.readline()
        remainbytes -= len(line)
        line = self.rfile.readline()
        remainbytes -= len(line)
        try:
            out = open(fn, 'wb')
        except IOError:
            return (False, "Can't create file to write, do you have permission to write?")

        preline = self.rfile.readline()
        remainbytes -= len(preline)
        while remainbytes > 0:
            line = self.rfile.readline()
            remainbytes -= len(line)
            if boundary in line:
                preline = preline[0:-1]
                if preline.endswith(b'\r'):
                    preline = preline[0:-1]
                out.write(preline)
                out.close()
                return (True, "File '%s' upload success!" % fn)
            else:
                out.write(preline)
                preline = line
        return (False, "Unexpect Ends of data.")

    def send_head(self):
        """Common code for GET and HEAD commands.

        This sends the response code and MIME headers.

        Return value is either a file object (which has to be copied
        to the outputfile by the caller unless the command was HEAD,
        and must be closed by the caller under all circumstances), or
        None, in which case the caller has nothing further to do.

        """
        path = self.translate_path()
        f = None
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype = self.guess_type(path)
        try:
            # Always read in binary mode. Opening files in text mode may cause
            # newline translations, making the actual size of the content
            # transmitted *less* than the content-length!
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None
        self.send_response(200)
        self.send_header("Content-type", ctype)
        fs = os.fstat(f.fileno())
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        """
        filename = os.path.basename(__file__)
        remove_file = ["cert.pem", filename]
        try:
            list = os.listdir(path)
            for file in remove_file:
                try:
                    list.remove(file)
                except ValueError:
                    pass

        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        f = BytesIO()
        displaypath = html.escape(urllib.parse.unquote(self.path))
        f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write(b"<h2 style='color:Tomato; text-align: center;'>WASABIHTTPSSERVER</h2>")
        f.write(("<html>\n<title>Directory listing for %s</title>\n" % displaypath).encode())
        f.write(("<body>\n<h2>Directory listing for %s</h1>\n" % displaypath).encode())
        f.write(b"<hr>\n")
        f.write(b"<form ENCTYPE=\"multipart/form-data\" method=\"post\">")
        f.write(b"<input name=\"file\" type=\"file\"/>")
        f.write(b"<input type=\"submit\" value=\"upload\"/></form>\n")
        f.write(b"<hr>\n<ul>\n")
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # Note: a link to a directory displays with @ and links with /
            f.write(('<li><a href="%s">%s</a>\n'
                     % (urllib.parse.quote(linkname), html.escape(displayname))).encode())
        f.write(b"</ul>\n<hr>\n</body>\n</html>\n")
        f.write(b"<p style='font-size:70%;'><a href='https://github.com/ECHO-3CK0/WASABIHTTPSServer'>&copy; 3CK0</a></p>")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

    def translate_path(self):
        """Translate a /-separated PATH to the local filename syntax.
        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = self.download_path
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        path = posixpath.normpath(urllib.parse.unquote(path))
        words = path.split('/')
        words = [_f for _f in words if _f]
        if path == "":
            path = os.getcwd()         #Download Path
            for word in words:
                drive, word = os.path.splitdrive(word)
                head, word = os.path.split(word)
                if word in (os.curdir, os.pardir): continue
                path = os.path.join(path, word)
        return path

    def translate_upload_path(self):
        """Translate a /-separated PATH to the local filename syntax.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = self.upload_path
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        path = posixpath.normpath(urllib.parse.unquote(path))
        words = path.split('/')
        words = [_f for _f in words if _f]
        if path == None:
            path = os.getcwd()      #Set upload path to current directory if is empty
            for word in words:
                drive, word = os.path.splitdrive(word)
                head, word = os.path.split(word)
                if word in (os.curdir, os.pardir): continue
                path = os.path.join(path, word)
        return path

    def copyfile(self, source, outputfile):
        """Copy all data between two file objects.

        The SOURCE argument is a file object open for reading
        (or anything with a read() method) and the DESTINATION
        argument is a file object open for writing (or
        anything with a write() method).

        The only reason for overriding this would be to change
        the block size or perhaps to replace newlines by CRLF
        -- note however that this the default server uses this
        to copy binary data as well.

        """
        shutil.copyfileobj(source, outputfile)

    def guess_type(self, path):
        """Guess the type of a file.

        Argument is a PATH (a filename).

        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.

        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.

        """

        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    def generate_selfsigned_cert():
        """Generates self signed certificate for a hostname"""
        hostname = gethostname()
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname)
        ])
        alt_names = [x509.DNSName(hostname)]

        san = x509.SubjectAlternativeName(alt_names)
        basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
        now = datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(1000)
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=365))
                .add_extension(basic_contraints, False)
                .add_extension(san, False)
                .sign(key, hashes.SHA256(), default_backend())
        )
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        f = open("cert.pem", "w")
        f.write(key_pem.decode())
        f.write(cert_pem.decode())
        f.close()

    if not mimetypes.inited:
        mimetypes.init()  # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream',  # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
    })


def __start__(options):
    banner()
    reset = Notification.REST
    print(f"{Notification.OK}{Notification.R[3]}Starting WEB Service.{reset}")

    if os.path.isfile("cert.pem"):
        print(f"{Notification.OK}{Notification.R[3]}Certificate found...{reset}")
    else:
        print(f"{Notification.ERROR}{Notification.R[2]}Certificate not found...{reset}")
        print(f"{Notification.WARN}{Notification.R[1]}Generating Certificate...{reset}")
        SimpleHTTPSRequestHandler.generate_selfsigned_cert()

    certificate_file = os.getcwd() + "/cert.pem"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_file)
    handler = SimpleHTTPSRequestHandler

    if options[0] == None:      #Checking IP address
        ip = "0.0.0.0"
    else:
        ip = options[0]

    if options[1] == None:                      #Checking Port Number
        port = 4443
    else:
        port = int(options[1])

    if options[2] == None:                      #Checking download path
        handler.download_path = os.getcwd()
    else:
        if os.path.exists(options[2]):
            handler.download_path = options[2]
        else:
            print(f"{Notification.ERROR}{Notification.R[2]}Download path was not found!{reset}")
            print(f"{Notification.WARN}{Notification.R[1]}Exiting...{reset}")
            exit()

    if options[3] == None:                      #Checking upload path
        handler.upload_path = os.getcwd()
    else:
        if os.path.exists(options[3]):
            handler.upload_path = options[3]
        else:
            print(f"{Notification.ERROR}{Notification.R[2]}Upload path was not found!{reset}")
            print(f"{Notification.WARN}{Notification.R[1]}Exiting...{reset}")
            exit()

    print(f"{Notification.OK}{Notification.R[3]}Ip address:{Notification.R[0]} {ip}{reset}")
    print(f"{Notification.OK}{Notification.R[3]}Port:{Notification.R[0]} {port}{reset}")
    print(f"{Notification.OK}{Notification.R[3]}Download path:{Notification.R[0]} {handler.download_path}{reset}")
    print(f"{Notification.OK}{Notification.R[3]}Upload path:{Notification.R[0]} {handler.upload_path}{reset}")
    server_address = (ip, port)

    try:
        with socketserver.TCPServer(server_address, handler) as httpd:
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            httpd.serve_forever()
    except OSError:
        print(f"{Notification.ERROR}{Notification.R[2]}Invalid IP address or port number is in use.")

def menu():
    options = []

    args = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent('''
    WASABI HTTPSServer
    '''),prog="WASABIHTTPServer.py")

    args.add_argument("-d", help="Download directory", metavar='', type=str)
    args.add_argument("-u", help="Upload directory", metavar='', type=str)
    args.add_argument("-p", help="Port number", metavar='',type=int)
    args.add_argument("-i", help="Ip address", metavar="", type=str)
    args.add_argument_group(argparse)

    args = args.parse_args()

    options.append(args.i)
    options.append(args.p)
    options.append(args.d)
    options.append(args.u)
    __start__(options)

if __name__ == '__main__':
    menu()
