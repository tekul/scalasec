package sec

import org.scalatest.mock.MockitoSugar
import org.springframework.security.core.userdetails.UserDetailsService
import org.scalatest.FlatSpec
import org.scalatest.matchers.ShouldMatchers
import org.springframework.security.openid.{OpenIDAuthenticationProvider, OpenIDAuthenticationFilter}

/**
 * @author Luke Taylor
 */

class OpenIDSpec extends FlatSpec with ShouldMatchers with MockitoSugar {
  val filterChainWithOpenID = new FilterChain with OpenID with LoginPageGenerator with AllowAllAuthentication {
    val userDetailsService = mock[UserDetailsService]
  }

  "A FilterChain with OpenID" should "have an OpenIDAuthenticationFilter" in {
    filterChainWithOpenID.filters.find(_.isInstanceOf[OpenIDAuthenticationFilter]) match {
      case Some(f) =>
      case None => fail("No OpenID filter found in stack")
    }
  }
  it should "Add an OpenIDAuthenticationProvider" in {
    filterChainWithOpenID.authenticationProviders.length should be (2)

    assert(filterChainWithOpenID.authenticationProviders.head.isInstanceOf[OpenIDAuthenticationProvider])
  }

}
