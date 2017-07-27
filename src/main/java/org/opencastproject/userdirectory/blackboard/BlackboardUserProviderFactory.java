/**
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.userdirectory.blackboard;

import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.OrganizationDirectoryService;
import org.opencastproject.security.api.RoleProvider;
import org.opencastproject.security.api.UserProvider;
import org.opencastproject.util.NotFoundException;

import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedServiceFactory;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.management.ManagementFactory;
import java.util.Arrays;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;

/**
 * Blackboard implementation of the spring UserDetailsService, taking configuration information from the component context.
 */
public class BlackboardUserProviderFactory implements ManagedServiceFactory {

  /** The logger */
  protected static final Logger logger = LoggerFactory.getLogger(BlackboardUserProviderFactory.class);

  /** This service factory's PID */
  public static final String PID = "org.opencastproject.userdirectory.blackboard";

  /** The key to look up the organization identifer in the service configuration properties */
  private static final String ORGANIZATION_KEY = "org.opencastproject.userdirectory.blackboard.org";

  /** The key to look up the URL of the Blackboard instance */
  private static final String BLACKBOARD_URL_KEY = "org.opencastproject.userdirectory.blackboard.url";

  /** The key to look up the list of Instructor roles on the Blackboard instance */
  private static final String BLACKBOARD_INSTRUCTOR_ROLES_KEY = "org.opencastproject.userdirectory.blackboard.instructor.roles";

  /** The key to look up the app key generated in Blackboard developer portal. */
  private static final String APPKEY_KEY = "org.opencastproject.userdirectory.blackboard.appkey";

  /** The key to look up the secret generated in Blackboard developer portal */
  private static final String SECRET_KEY = "org.opencastproject.userdirectory.blackboard.secret";

  /** The key to look up the regular expression used to validate sites */
  private static final String SITE_PATTERN_KEY = "org.opencastproject.userdirectory.blackboard.site.pattern";

  /** The key to look up the regular expression used to validate users */
  private static final String USER_PATTERN_KEY = "org.opencastproject.userdirectory.blackboard.user.pattern";

  /** The key to look up the number of user records to cache */
  private static final String USER_CACHE_SIZE = "org.opencastproject.userdirectory.blackboard.cache.size";

  /** The default number of user records to cache */
  private static final int USER_CACHE_SIZE_DEFAULT = 1000;

  /** The key to look up the number of minutes to cache users */
  private static final String USER_CACHE_EXPIRATION = "org.opencastproject.userdirectory.blackboard.cache.expiration";

  /** The default number of minutes to expire user records from cache */
  private static final int USER_CACHE_EXPIRATION_DEFAULT = 60;

  /** The key to look up the number of course records to cache */
  private static final String COURSE_CACHE_SIZE = "org.opencastproject.userdirectory.blackboard.coursecache.size";

  /** The default number of course ids to cache */
  private static final int COURSE_CACHE_SIZE_DEFAULT = 5000;

  /** The key to look up the number of minutes to cache course lookups */
  private static final String COURSE_CACHE_EXPIRATION = "org.opencastproject.userdirectory.blackboard.coursecache.expiration";

  /** The default number of minutes to expire course id records from cache */
  private static final int COURSE_CACHE_EXPIRATION_DEFAULT = 525600;

  /** A map of pid to blackboard user provider instance */
  private Map<String, ServiceRegistration> providerRegistrations = new ConcurrentHashMap<String, ServiceRegistration>();;

  /** The OSGI bundle context */
  protected BundleContext bundleContext = null;

  /** The organization directory service */
  private OrganizationDirectoryService orgDirectory;

  /** OSGi callback for setting the organization directory service. */
  public void setOrgDirectory(OrganizationDirectoryService orgDirectory) {
    this.orgDirectory = orgDirectory;
  }

  /**
   * Callback for the activation of this component
   *
   * @param cc
   *          the component context
   */
  public void activate(ComponentContext cc) {
    logger.debug("Activate BlackboardUserProviderFactory");
    this.bundleContext = cc.getBundleContext();
  }

  /**
   * {@inheritDoc}
   *
   * @see org.osgi.service.cm.ManagedServiceFactory#getName()
   */
  @Override
  public String getName() {
    return PID;
  }

  /**
   * {@inheritDoc}
   *
   * @see org.osgi.service.cm.ManagedServiceFactory#updated(java.lang.String, java.util.Dictionary)
   */
  @Override
  public void updated(String pid, Dictionary properties) throws ConfigurationException {

    logger.debug("updated BlackboardUserProviderFactory");

    String organization = (String) properties.get(ORGANIZATION_KEY);
    if (StringUtils.isBlank(organization)) throw new ConfigurationException(ORGANIZATION_KEY, "is not set");

    String url = (String) properties.get(BLACKBOARD_URL_KEY);
    if (StringUtils.isBlank(url)) throw new ConfigurationException(BLACKBOARD_URL_KEY, "is not set");

    String appKey = (String) properties.get(APPKEY_KEY);
    String secret = (String) properties.get(SECRET_KEY);

    String sitePattern = (String) properties.get(SITE_PATTERN_KEY);
    String userPattern = (String) properties.get(USER_PATTERN_KEY);

    int userCacheSize = getIntProperty(properties, USER_CACHE_SIZE, USER_CACHE_SIZE_DEFAULT);
    int userCacheExpiration = getIntProperty(properties, USER_CACHE_EXPIRATION, USER_CACHE_EXPIRATION_DEFAULT);

    int courseCacheSize = getIntProperty(properties, COURSE_CACHE_SIZE, COURSE_CACHE_SIZE_DEFAULT);
    int courseCacheExpiration = getIntProperty(properties, COURSE_CACHE_EXPIRATION, COURSE_CACHE_EXPIRATION_DEFAULT);

    // Instructor roles
    Set<String> instructorRoles;
    String instructorRoleList = (String) properties.get(BLACKBOARD_INSTRUCTOR_ROLES_KEY);

    if (!StringUtils.isEmpty(instructorRoleList)) {
      String trimmedRoles = StringUtils.trim(instructorRoleList);
      String[] roles = trimmedRoles.split(",");
      instructorRoles = new HashSet<String>(Arrays.asList(roles));
      logger.info("Blackboard instructor roles: {}", Arrays.toString(roles));
    } else {
      // Default instructor roles
      instructorRoles = new HashSet<String>();
      instructorRoles.add("Site owner");
      instructorRoles.add("Instructor");
      instructorRoles.add("maintain");
    }

    // Now that we have everything we need, go ahead and activate a new provider, removing an old one if necessary
    ServiceRegistration existingRegistration = providerRegistrations.remove(pid);
    if (existingRegistration != null) {
      existingRegistration.unregister();
    }

    Organization org;
    try {
      org = orgDirectory.getOrganization(organization);
    } catch (NotFoundException e) {
      logger.warn("Organization {} not found!", organization);
      throw new ConfigurationException(ORGANIZATION_KEY, "not found");
    }

    logger.debug("creating new BlackboardUserProviderInstance for pid=" + pid);
    BlackboardUserProviderInstance provider = new BlackboardUserProviderInstance(pid,
            org, url, appKey, secret, sitePattern, userPattern, instructorRoles,
            userCacheSize, userCacheExpiration, courseCacheSize, courseCacheExpiration);

    providerRegistrations.put(pid, bundleContext.registerService(UserProvider.class.getName(), provider, null));
    providerRegistrations.put(pid, bundleContext.registerService(RoleProvider.class.getName(), provider, null));

  }

  private int getIntProperty(Dictionary properties, String property, int defaultValue) {
    int value = defaultValue;
    try {
      if (properties.get(property) != null) {
        Integer configuredValue = Integer.parseInt(properties.get(property).toString());
        if (configuredValue != null) {
          value = configuredValue.intValue();
        }
      }
    } catch (Exception e) {
      logger.warn("{} could not be loaded, default value is used: {}", property, value);
    }
    return value;
  }

  /**
   * {@inheritDoc}
   *
   * @see org.osgi.service.cm.ManagedServiceFactory#deleted(java.lang.String)
   */
  @Override
  public void deleted(String pid) {
    logger.debug("delete BlackboardUserProviderInstance for pid=" + pid);
    ServiceRegistration registration = providerRegistrations.remove(pid);
    if (registration != null) {
      registration.unregister();
      try {
        ManagementFactory.getPlatformMBeanServer().unregisterMBean(BlackboardUserProviderFactory.getObjectName(pid));
      } catch (Exception e) {
        logger.warn("Unable to unregister mbean for pid='{}': {}", pid, e.getMessage());
      }
    }
  }

  /**
   * Builds a JMX object name for a given PID
   *
   * @param pid
   *          the PID
   * @return the object name
   * @throws NullPointerException
   * @throws MalformedObjectNameException
   */
  public static final ObjectName getObjectName(String pid) throws MalformedObjectNameException, NullPointerException {
    return new ObjectName(pid + ":type=BlackboardRequests");
  }

}
