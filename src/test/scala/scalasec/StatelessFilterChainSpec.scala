package scalasec


import org.scalatest.FlatSpec
import org.scalatest.matchers.ShouldMatchers
import org.scalatest.mock.MockitoSugar
import org.springframework.security.authentication.AuthenticationManager
import org.mockito.Mockito._
import org.springframework.security.core.Authentication
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter

/**
 * @author Luke Taylor
 */
class StatelessFilterChainSpec extends FlatSpec with ShouldMatchers with TestConversions with MockitoSugar {

  "a StatelessFilterChain" should "allow setting of an AuthenticationManager" in {
    val am = mock[AuthenticationManager]
    val a = mock[Authentication]
    when(am.authenticate(a)).thenReturn(a)

    val fc = new StatelessFilterChain {
      val authenticationManager = am
    }

    fc.internalAuthenticationManager.authenticate(a) should be (a)
  }
  it should "allow easy insertion of additional filters" in {
    val chain = new StatelessFilterChain with AllowAllAuthentication with InsertionHelper {
      override def filters = {
        insertAfter(classOf[ExceptionTranslationFilter], new X509AuthenticationFilter, super.filters)
      }
    }

    assert(chain.filters(3).isInstanceOf[X509AuthenticationFilter])

    val chain2 = new StatelessFilterChain with AllowAllAuthentication with InsertionHelper {
      override def filters = {
        insertBefore(classOf[ExceptionTranslationFilter], new X509AuthenticationFilter, super.filters)
      }
    }

    assert(chain2.filters(2).isInstanceOf[X509AuthenticationFilter])
  }

}
