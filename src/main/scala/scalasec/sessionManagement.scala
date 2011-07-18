package scalasec

import javax.servlet.Filter
import FilterPositions._
import org.springframework.security.web.session.{ConcurrentSessionFilter, SessionManagementFilter}
import org.springframework.security.web.authentication.session.{ConcurrentSessionControlStrategy, SessionFixationProtectionStrategy, NullAuthenticatedSessionStrategy, SessionAuthenticationStrategy}
import org.springframework.context.ApplicationListener
import org.springframework.security.core.session.{SessionRegistryImpl, SessionDestroyedEvent, SessionRegistry}

/**
 * Exposes the shared <code>SessionAuthenticationStrategy</code> reference.
 */
private[scalasec] trait SessionAuthentication {
  val sessionAuthenticationStrategy: SessionAuthenticationStrategy = new NullAuthenticatedSessionStrategy
}

/**
 * Creates the default <code>SessionFixationProtectionStrategy</code> for use in a session-based app and adds
 * the <code>SessionManagementFilter</code>
 */
trait SessionManagement extends StatelessFilterChain with SessionAuthentication {
  override val sessionAuthenticationStrategy: SessionAuthenticationStrategy = new SessionFixationProtectionStrategy

  lazy val sessionManagementFilter: Filter = new SessionManagementFilter(securityContextRepository, sessionAuthenticationStrategy)

  override def filtersInternal = (SESSION_MANAGEMENT_FILTER, sessionManagementFilter) :: super.filtersInternal
}

trait ConcurrentSessionControl extends SessionManagement with ApplicationListener[SessionDestroyedEvent] {
  private var delegateEvents: Boolean = false
  lazy val sessionRegistry: SessionRegistry = {
    // SessionRegistry has not been overridden, so we need to delegate events to it
    delegateEvents = true
    new SessionRegistryImpl
  }
  val sessionExpiredUrl: String = null

  override val sessionAuthenticationStrategy = new ConcurrentSessionControlStrategy(sessionRegistry)

  val concurrentSessionFilter = new ConcurrentSessionFilter(sessionRegistry, sessionExpiredUrl)

  override def filtersInternal = (CONCURRENT_SESSION_FILTER, concurrentSessionFilter) :: super.filtersInternal

  def onApplicationEvent(event: SessionDestroyedEvent) {
    if (delegateEvents) {
      sessionRegistry.asInstanceOf[SessionRegistryImpl].onApplicationEvent(event)
    }
  }
}
