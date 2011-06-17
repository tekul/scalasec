package sec

import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.{LoginUrlAuthenticationEntryPoint, UsernamePasswordAuthenticationFilter}
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.authentication.www.{BasicAuthenticationEntryPoint, BasicAuthenticationFilter}
import org.springframework.security.web.util.{AnyRequestMatcher, AntPathRequestMatcher, RequestMatcher}
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter
import collection.immutable.ListMap

import javax.servlet.Filter
import org.springframework.security.web.access.intercept.{DefaultFilterInvocationSecurityMetadataSource, FilterInvocationSecurityMetadataSource, FilterSecurityInterceptor}
import org.springframework.security.access.{SecurityConfig, ConfigAttribute}

import java.{util => ju}
import org.springframework.security.web.access.expression.{DefaultWebSecurityExpressionHandler, ExpressionBasedFilterInvocationSecurityMetadataSource}
import org.springframework.context.annotation.Lazy

object RequiredChannel extends Enumeration {
  val Http, Https, Any = Value
}

trait Conversions {
  implicit def stringToRequestMatcher(pattern: String) = pattern match {
    case "**" | "/**" => new AnyRequestMatcher()
    case _  => new AntPathRequestMatcher(pattern)
  }

  implicit def requestMatcherMapAsLinkedHashMap[A, B](m : ListMap[A, B]): ju.LinkedHashMap[A, B] = {
    val result = new ju.LinkedHashMap[A,B]
    m foreach { case (key, value) => result.put(key, value)}
    result
  }
}

object Conversions extends Conversions

/**
 *
 * @author Luke Taylor
 */
trait FilterChain extends Conversions {
  val securityContextPersistenceFilter = new SecurityContextPersistenceFilter()
  val exceptionTranslationFilter = new SecurityContextPersistenceFilter()
  val requestCacheFilter = new RequestCacheAwareFilter()
  val filterSecurityInterceptor = new FilterSecurityInterceptor()

  private var channels : ListMap[RequestMatcher, RequiredChannel.Value] = ListMap()
  private[sec] var accessUrls : ListMap[RequestMatcher, ju.List[ConfigAttribute]] = ListMap()

  private[sec] lazy val securityMetadataSource : FilterInvocationSecurityMetadataSource
          = new DefaultFilterInvocationSecurityMetadataSource(accessUrls)


  def filters : List[Filter] = {
    filterSecurityInterceptor.setSecurityMetadataSource(securityMetadataSource)

    securityContextPersistenceFilter :: requestCacheFilter :: exceptionTranslationFilter :: filterSecurityInterceptor :: Nil
  }

  def entryPoint : AuthenticationEntryPoint

  def addInterceptUrl(matcher : RequestMatcher, access : String, channel : RequiredChannel.Value = RequiredChannel.Any) {
    accessUrls = accessUrls + (matcher -> createConfigAttributes(access))
    channels = channels + (matcher -> channel)
  }

  private[sec] def createConfigAttributes(access : String) : ju.List[ConfigAttribute] = {
    SecurityConfig.createList(access.split(",") : _*);
  }
}

trait ELConfiguration extends FilterChain {
  val expressionHandler = new DefaultWebSecurityExpressionHandler()

  override lazy val securityMetadataSource = new ExpressionBasedFilterInvocationSecurityMetadataSource(accessUrls, expressionHandler)

  override def createConfigAttributes(access : String) : ju.List[ConfigAttribute] = {
    SecurityConfig.createList(access);
  }
}

trait FormLogin extends FilterChain {
  val formLoginFilter = new UsernamePasswordAuthenticationFilter()
  val formLoginEntryPoint = new LoginUrlAuthenticationEntryPoint()

  def loginPage(url : String) {
    formLoginEntryPoint.setLoginFormUrl(url)
  }

  override def filters = {
    super.filters.head :: formLoginFilter :: super.filters.tail
  }

  override def entryPoint : AuthenticationEntryPoint = formLoginEntryPoint
}

trait BasicAuthentication extends FilterChain {
  val basicAuthenticationFilter = new BasicAuthenticationFilter()
  val basicAuthenticationEntryPoint = new BasicAuthenticationEntryPoint()

  override def filters = {
    super.filters.head :: basicAuthenticationFilter :: super.filters.tail
  }

  override def entryPoint : AuthenticationEntryPoint = basicAuthenticationEntryPoint
}
