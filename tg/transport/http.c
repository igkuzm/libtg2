#include "http.h"
#include "../../libtg.h"
#include "../tg.h"
#include "../tg_log.h"
#include "../dc.h"
#include <curl/curl.h>
#include <curl/easy.h>
#include <stdio.h>
#include <sys/select.h>

#define VERIFY_SSL 0

/*  HTTPS
 *
 *  To establish a connection over HTTPS, simply use the TLS
 *  URI format. The rest is the same as with plain HTTP.
 *
 *  URI format
 *
 *  The URI format that must be used when connecting to the
 *  plain WebSocket and HTTP endpoints is the following:
 *
 *  http://X.X.X.X:80/api(w)(s)
 *
 *  The following URI may also be used only for HTTP and
 *  secure WebSocket endpoints (not usable for plain
 *  WebSocket connections):
 *
 *  http://(name)(-1).web.telegram.org:80/api(w)(s)(_test)
 *
 *  The w flag is added when CORS headers are required in
 *  order to connect from a browser.
 *  The s flag enables the WebSocket API.
 *  The name placeholder in the domain version specifies
 *  the DC ID to connect to:
 *
 * • pluto => DC 1
 * • venus => DC 2
 * • aurora => DC 3
 * • vesta => DC 4
 * • flora => DC 5
 *
 *  -1 can be appended to the DC name to raise
 *  the maximum limit of simultaneous requests
 *  per hostname.
 *  The _test flag, when connecting to the domain
 *  version of the URL, specifies that connection
 *  to the test DCs must be made, instead.
 */

#define URI    "%s%s.web.telegram.org:%d/api%s"
#define URI_IP "%s:%d/api%s"

static size_t tg_http_readfunc(
		unsigned char *data, size_t s, size_t n, 
		buf_t *buf)
{
	/*printf("%s: len %ld\n", __func__, s*n);*/
	size_t size = s * n;
	
	if (size > buf->size)
		size = buf->size;

	memcpy(data, buf->data, size);
	
	buf->data += size;
	buf->size -= size;

	return s;
}

static size_t tg_http_writefunc(
		unsigned char  *data, size_t s, size_t n, 
		buf_t *buf)
{
	printf("%s: len %ld\n", __func__, s*n);

	size_t len = s * n;
	*buf = buf_cat_data(*buf, data, len);

  return len;
}

//CURLcode tg_http_open_connection(
		//tg_t *tg, enum dc dc, int port, 
		//bool maximum_limit, bool test)
//{
	//char url[BUFSIZ];
	//snprintf(url, BUFSIZ-1, URI_IP, 
			//DCs[dc].ipv4, port, test?"_test":"");
	
	//ON_LOG(tg, "%s: open url: %s", __func__, url);
	
	//curl_easy_setopt(tg->curl, CURLOPT_URL, url);
	//curl_easy_setopt(tg->curl, CURLOPT_CONNECT_ONLY, 1L);
  
	//curl_easy_setopt(tg->curl, CURLOPT_SSL_VERIFYPEER, VERIFY_SSL);		
  //curl_easy_setopt(tg->curl, CURLOPT_TCP_KEEPALIVE, 1L);
  
	/*buf_t buf = buf_new();*/

	/*curl_easy_setopt(tg->curl, CURLOPT_WRITEDATA, &buf);		*/
	/*curl_easy_setopt(tg->curl, CURLOPT_WRITEFUNCTION, tg_http_writefunc);*/
	

	/*return curl_easy_perform(tg->curl);*/
	/*return curl_easy_perform(tg->curl);*/
/*}*/

/*buf_t tg_http_send(tg_t *tg, buf_t *query)*/
/*{*/
	/*curl_socket_t sockfd;*/
  /*size_t sent = 0;*/
  
	/*buf_t buf = buf_new();*/

	/*curl_easy_setopt(tg->curl, CURLOPT_WRITEDATA, &buf);		*/
	/*curl_easy_setopt(tg->curl, CURLOPT_WRITEFUNCTION, tg_http_writefunc);*/
	
	/* Extract the socket from the curl handle - we need it for waiting. */
  /*if (curl_easy_getinfo(tg->curl, CURLINFO_ACTIVESOCKET, &sockfd) != CURLE_OK)*/
	/*{*/
		/*ON_ERR(tg, "%s: curl_easy_getinfo error", __func__);*/
	/*};*/

  /*[> send data <]*/
	/*while (sent < query->size){*/
		/*if (curl_easy_send(*/
				/*tg->curl, query->data, query->size, &sent) != CURLE_OK)*/
		/*{*/
			/*ON_ERR(tg, "%s: curl_easy_send error", __func__);*/
		/*}*/
	/*}*/

	/*ON_LOG(tg, "%s: query size: %d", __func__, query->size);*/
	/*ON_LOG(tg, "%s: sent data: %ld", __func__, sent);*/

	/*return buf;*/
/*}*/

/*buf_t tg_http_recieve(tg_t *tg)*/
/*{*/
	/*curl_socket_t sockfd;*/
	/*size_t nread;*/
	/*buf_t buf = buf_new();*/
	/*CURLcode res;*/
  
	/*[> Extract the socket from the curl handle - we need it for waiting. <]*/
  /*if (curl_easy_getinfo(tg->curl, CURLINFO_ACTIVESOCKET, &sockfd) != CURLE_OK)*/
	/*{*/
		/*ON_ERR(tg, "%s: curl_easy_getinfo error", __func__);*/
	/*};*/

  /*[> rescieve data <]*/
	/*res = CURLE_AGAIN;*/
	/*while (res == CURLE_AGAIN) {*/
		/*res = curl_easy_recv(tg->curl, buf.data, */
				/*buf.size, &nread); */
		/*if (res != CURLE_OK && res != CURLE_AGAIN)*/
		/*{*/
			/*ON_ERR(tg, "%s: curl_easy_recv error: %d", __func__, res);*/
		/*}*/
	/*}*/

	/*ON_LOG(tg, "%s: received: %ld", __func__, nread);*/
	/*return buf;*/
/*}*/

buf_t tg_http_send_query(
		tg_t *tg, enum dc dc, int port, bool maximum_limit, 
		bool test, buf_t *query,
		void *ptr, 
		tg_progress_fun *progress)
{
	buf_t buf = buf_new();
	
	CURL *curl = curl_easy_init();
	if (!curl){
		ON_ERR(tg, "%s: can't init curl", __func__);
		return buf;
	}
	
	//debug
	/*curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);*/
		
	char url[BUFSIZ];
	/*snprintf(url, BUFSIZ-1, URI, */
			/*DCs[dc].name, maximum_limit?"-1":"", port, test?"_test":"");*/
	snprintf(url, BUFSIZ-1, URI_IP, 
			DCs[dc].ipv4, port, test?"_test":"");
	
	ON_LOG(tg, "%s: open url: %s", __func__, url);
	
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");		

	curl_easy_setopt(curl, CURLOPT_HEADER, 0);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);		
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query->data);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, query->size);

	/* enable TCP keep-alive for this transfer */
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

	/*curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);*/
	/*curl_easy_setopt(curl, CURLOPT_READDATA, query);*/
	/*curl_easy_setopt(curl, CURLOPT_READFUNCTION, tg_http_readfunc);*/
	/*curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, query->size);*/
		
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);		
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tg_http_writefunc);

  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, VERIFY_SSL);		

	if (progress) {
#if LIBCURL_VERSION_NUM < 0x072000
		curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, ptr);
		curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, 
				progress);
#else
		curl_easy_setopt(curl, CURLOPT_XFERINFODATA, ptr);
		curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, 
				progress);
#endif
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
	}
		
	CURLcode err = curl_easy_perform(curl);
	//curl_easy_cleanup(curl);
	//if (err){
		//ON_ERR(tg, "%s: %s", __func__, curl_easy_strerror(err));
		//return buf;
	//}

	/* now extract transfer info */
	curl_off_t usize, dsize;
	curl_easy_getinfo(curl, 
			CURLINFO_CONTENT_LENGTH_UPLOAD_T, &usize);
	ON_LOG(tg, "%s: uploaded: %ld", __func__, usize);
	
	curl_easy_getinfo(curl, 
			CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &dsize);
	ON_LOG(tg, "%s: downloaded: %ld", __func__, dsize);
	
	/* always cleanup */
	curl_easy_cleanup(curl);
	//curl_slist_free_all(header);
	
	return buf;
}	
