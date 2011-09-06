package sample

import javax.servlet.http.HttpServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.core.context.SecurityContextHolder

/**
 * @author Luke Taylor
 */
class SampleServlet extends HttpServlet {
  protected override def doGet(req: HttpServletRequest, res: HttpServletResponse) {
    res.getWriter.write(
      <html>
        <head><title>Security Sample</title></head>
        <body>
          <p>Hello, your request was:
<pre>
{req}
</pre>
          </p>
          <p>{"Current security context contents: " + SecurityContextHolder.getContext.getAuthentication}</p>
        </body>
      </html>.toString()
    )
  }

}
