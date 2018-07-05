import base64
import optparse


def useage():
    print "python base.py -b64/32/16 decode"
    print "For Examgle:"
    print "python base.py -b64 bmloYW8="


def b64(s1):
	print base64.b64decode(s1)
def b32(s2):
	print base64.b32decode(s2)
def b16(s3):
	print base64.b16decode(s3)
	
	
if __name__ == '__main__':
	parser = optparse.OptionParser()
	parser.add_option('--b64',dest='b64',nargs=1,help='decode base64 strings')
	parser.add_option('--b32',dest='b32',nargs=1,help='decode base32 strings')
	parser.add_option('--b16',dest='b16',nargs=1,help='decode base16 strings')
	
	try:
		(options,args) = parser.parse_args()
		#print options
		if options.b64:
			b64(options.b64)
		elif options.b32:
			b32(options.b32)
		elif options.b16:
			b16(options.b16)					
		
	except optparse.OptionValueError as e:
		parser.print_help()
		parser.error(e.msg)