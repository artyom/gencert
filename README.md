gencert creates server + client certificates signed with the same
self-issued CA

	Usage of gencert:
	  -client.cert string
		file to save client certificate (default "client-cert.pem")
	  -client.key string
		file to save client certificate key (default "client-key.pem")
	  -hosts string
		comma-separated list of hostnames
	  -server.cert string
		file to save server certificate (default "server-cert.pem")
	  -server.key string
		file to save server certificate key (default "server-key.pem")

Both client and server saved certificates are concatenated with CA certificate
they were signed with. This CA can be used by either side to verify
authenticity of certificate presented by other party.
