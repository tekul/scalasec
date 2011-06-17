package sec

import org.scalatest.FlatSpec
import org.scalatest.matchers.ShouldMatchers
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint

import Conversions._
import org.springframework.security.web.access.intercept.{FilterSecurityInterceptor, DefaultFilterInvocationSecurityMetadataSource}
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource

/**
 *
 * @author Luke Taylor
 */
class FilterChainSpec extends FlatSpec with ShouldMatchers {

  "A FilterChain" should
      "support adding of intercept URLs to security interceptor" in {
    val chain = new FilterChain {
      val entryPoint = new LoginUrlAuthenticationEntryPoint
      override val filterSecurityInterceptor = new FilterSecurityInterceptor
    }

    chain.addInterceptUrl(matcher = "/AAA", access = "AAA")
    chain.addInterceptUrl("/**", "BBB")
    chain.addInterceptUrl("**", "CCC")

    chain.filters

    val mds = chain.filterSecurityInterceptor.getSecurityMetadataSource match {
      case d : DefaultFilterInvocationSecurityMetadataSource => d
      case _ => fail("Expected DefaultFilterInvocationSecurityMetadataSource")
    }

    mds.getAllConfigAttributes.size() should be (2)
  }

  "A FilterChain with FormLogin" should
      "have a LoginUrlAuthenticationEntryPoint" in {
    val chain = new FilterChain with FormLogin

    chain.entryPoint should be (chain.formLoginEntryPoint)
  }

  it should "have 5 filters" in {
    val chain = new FilterChain with FormLogin

    chain.filters.length should be (5)
  }

  "A FilterChain with BasicAuthentication with FormLogin " should
      "have a LoginUrlAuthenticationEntryPoint" in {
    val chain = new FilterChain with BasicAuthentication with FormLogin

    chain.entryPoint should be theSameInstanceAs (chain.formLoginEntryPoint)
  }

  "A FilterChain with FormLogin with BasicAuthentication" should
      "have a BasicAuthenticationEntryPoint" in {
    val chain = new FilterChain with FormLogin with BasicAuthentication

    chain.entryPoint should be theSameInstanceAs (chain.basicAuthenticationEntryPoint)
  }
  it should "have 6 filters" in {
    val chain = new FilterChain with FormLogin with BasicAuthentication

    chain.filters.length should be (6)
  }

  "A FilterChain with ELConfiguration" should
    "have an Expression SecurityMDS" in {
    val chain = new FilterChain with FormLogin with ELConfiguration

    chain.addInterceptUrl(matcher = "/AAA", access = "permitAll")
    chain.addInterceptUrl("/**", "hasAnyRole('a','b','c')")

    val mds = chain.filterSecurityInterceptor.getSecurityMetadataSource match {
      case d : ExpressionBasedFilterInvocationSecurityMetadataSource => d
      case _ => fail("Expected ExpressionBasedFilterInvocationSecurityMetadataSource ")
    }

    mds.getAllConfigAttributes.size() should be (2)
  }



}
