package scalasec

import org.springframework.security.core.userdetails.UserDetailsService

/**
 * Provides a UserDetailsService reference to services which require it
 *
 * @author Luke Taylor
 */
trait UserService {
  val userDetailsService: UserDetailsService
//  lazy val userDetailsService: UserDetailsService = {
//    throw new AssertionError("You need to set the userDetailsService")
//  }
}
