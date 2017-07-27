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

import org.opencastproject.security.api.CachingUserProviderMXBean;
import org.opencastproject.security.api.Group;
import org.opencastproject.security.api.JaxbOrganization;
import org.opencastproject.security.api.JaxbRole;
import org.opencastproject.security.api.JaxbUser;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.Role;
import org.opencastproject.security.api.RoleProvider;
import org.opencastproject.security.api.User;
import org.opencastproject.security.api.UserProvider;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.ExecutionError;
import com.google.common.util.concurrent.UncheckedExecutionException;

import com.google.gson.Gson;
// import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
// import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

// import java.io.StringReader;
import java.lang.management.ManagementFactory;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.PatternSyntaxException;

import javax.management.InstanceNotFoundException;
import javax.management.MBeanServer;
import javax.management.ObjectName;
// import javax.xml.parsers.DocumentBuilder;
// import javax.xml.parsers.DocumentBuilderFactory;

/**
 * A UserProvider that reads user roles from Blackboard.
 */
public class BlackboardUserProviderInstance implements UserProvider, RoleProvider, CachingUserProviderMXBean {

  private static final String LTI_LEARNER_ROLE = "Learner";

  private static final String LTI_INSTRUCTOR_ROLE = "Instructor";

  public static final String PROVIDER_NAME = "blackboard";

  private static final String OC_USERAGENT = "Opencast";

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(BlackboardUserProviderInstance.class);

  /** The organization */
  private Organization organization = null;

  /** Total number of requests made to load users */
  private AtomicLong requests = null;

  /** The number of requests made to Blackboard */
  private AtomicLong blackboardLoads = null;

  /** A cache of users, which lightens the load on Blackboard */
  private LoadingCache<String, Object> userCache = null;

  /** A cache of courseId mappings, which lightens the load on Blackboard */
  private LoadingCache<String, String> courseIdCache = null;

  /** A token to store in the miss cache */
  protected Object nullToken = new Object();

  /** The URL of the Blackboard instance */
  private String blackboardUrl = null;

  /** The app key generated in Blackboard developer portal */
  private String appKey = null;

  /** The secret generated in Blackboard developer portal */
  private String secret = null;

  /** Oauth2 bearer token from Blackboard **/
  private String bearerToken = null;

  /** Regular expression for matching valid sites */
  private String sitePattern;

  /** Regular expression for matching valid users */
  private String userPattern;

  /** A map of roles which are regarded as Instructor roles */
  private Set<String> instructorRoles;

  /**
   * Constructs an Blackboard user provider with the needed settings.
   *
   * @param pid
   *          the pid of this service
   * @param organization
   *          the organization
   * @param url
   *          the url of the Blackboard server
   * @param userName
   *          the user to authenticate as
   * @param password
   *          the user credentials
   * @param userCacheSize
   *          the number of users to cache
   * @param userCacheExpiration
   *          the number of minutes to cache users
   */
  public BlackboardUserProviderInstance(String pid, Organization organization, String url, String appKey, String secret,
          String sitePattern, String userPattern, Set<String> instructorRoles,
          int userCacheSize, int userCacheExpiration, int courseCacheSize, int courseCacheExpiration) {

    this.organization = organization;
    this.blackboardUrl = url;
    this.appKey = appKey;
    this.secret = secret;
    this.sitePattern = sitePattern;
    this.userPattern = userPattern;
    this.instructorRoles = instructorRoles;

    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);

    logger.info("Creating new BlackboardUserProviderInstance(pid={}, url={}, userCacheSize={}, userCacheExpiration={}, courseCacheSize={}, courseCacheExpiration={})",
                 pid, url, userCacheSize, userCacheExpiration, courseCacheSize, courseCacheExpiration);

    // Setup the caches
    userCache = CacheBuilder.newBuilder().maximumSize(userCacheSize).expireAfterWrite(userCacheExpiration, TimeUnit.MINUTES)
                .build(new CacheLoader<String, Object>() {
                  @Override
                  public Object load(String id) throws Exception {
                    User user = loadUserFromBlackboard(id);
                    return user == null ? nullToken : user;
                  }
                });

    courseIdCache = CacheBuilder.newBuilder().maximumSize(courseCacheSize).expireAfterWrite(courseCacheExpiration, TimeUnit.MINUTES)
                    .build(new CacheLoader<String, String>() {
                      @Override
                      public String load(String id) throws Exception {
                        String courseId = loadCourseIdFromBlackboard(id);
                        return courseId == null ? "" : courseId;
                      }
                    });

    registerMBean(pid);
  }

  @Override
  public String getName() {
    return PROVIDER_NAME;
  }

  /**
   * Registers an MXBean.
   */
  protected void registerMBean(String pid) {
    // register with jmx
    requests = new AtomicLong();
    blackboardLoads = new AtomicLong();
    try {
      ObjectName name;
      name = BlackboardUserProviderFactory.getObjectName(pid);
      Object mbean = this;
      MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
      try {
        mbs.unregisterMBean(name);
      } catch (InstanceNotFoundException e) {
        logger.debug(name + " was not registered");
      }
      mbs.registerMBean(mbean, name);
    } catch (Exception e) {
      logger.error("Unable to register {} as an mbean: {}", this, e);
    }
  }

  // UserProvider methods

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.UserProvider#getOrganization()
   */
  @Override
  public String getOrganization() {
    return organization.getId();
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.UserProvider#loadUser(java.lang.String)
   */
  @Override
  public User loadUser(String userName) {
    logger.debug("loaduser(" + userName + ")");
    requests.incrementAndGet();
    try {
      Object user = userCache.getUnchecked(userName);
      if (user == nullToken) {
        logger.debug("Returning null user from cache");
        return null;
      } else {
        logger.debug("Returning user " + userName + " from cache");
        return (JaxbUser) user;
      }
    } catch (ExecutionError e) {
      logger.warn("Exception while loading user {}", userName, e);
      return null;
    } catch (UncheckedExecutionException e) {
      logger.warn("Exception while loading user {}", userName, e);
      return null;
    }
  }

  /**
   * Loads a user from Blackboard.
   *
   * @param userName
   *          the username
   * @return the user
   */
  protected User loadUserFromBlackboard(String userName) {

    if (userCache == null) {
      throw new IllegalStateException("The Blackboard user detail service has not yet been configured");
    }

    // Don't answer for admin, anonymous or empty user
    if ("admin".equals(userName) || "".equals(userName) || "anonymous".equals(userName)) {
      userCache.put(userName, nullToken);
      logger.debug("we don't answer for: " + userName);
      return null;
    }

    logger.debug("In loadUserFromBlackboard, currently processing user : {}", userName);

    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);

    // update cache statistics
    blackboardLoads.incrementAndGet();

    Thread currentThread = Thread.currentThread();
    ClassLoader originalClassloader = currentThread.getContextClassLoader();
    try {

      // Blackboard display name and email address
      String[] blackboardUser = getBlackboardUser(userName);

      if (blackboardUser == null) {
        // user not known to this provider
        logger.debug("User {} not found in Blackboard system", userName);
        userCache.put(userName, nullToken);
        return null;
      }

      String displayName = blackboardUser[0];
      String email = blackboardUser[1];

      // Get the set of Blackboard roles for the user
      String[] blackboardRoles = getBlackboardCourseMemberships(userName);

      // if Blackboard doesn't know about this user we need to return
      if (blackboardRoles == null) {
        userCache.put(userName, nullToken);
        return null;
      }

      logger.debug("Blackboard roles for user " + userName + ": " + Arrays.toString(blackboardRoles));

      Set<JaxbRole> roles = new HashSet<JaxbRole>();
      boolean isInstructor = false;

      for (String r : blackboardRoles) {
        roles.add(new JaxbRole(r, jaxbOrganization, "Blackboard external role", Role.Type.EXTERNAL));
        if (r.endsWith("_" + LTI_INSTRUCTOR_ROLE)) {
          isInstructor = true;
        }
      }

      // Add a group role for testing
      roles.add(new JaxbRole(Group.ROLE_PREFIX + "BLACKBOARD", jaxbOrganization, "Blackboard Group", Role.Type.EXTERNAL_GROUP));

      // add a group for all instructors
      if (isInstructor) {
        roles.add(new JaxbRole(Group.ROLE_PREFIX + "BLACKBOARD_INSTRUCTOR", jaxbOrganization, "Blackboard Instructors Group", Role.Type.EXTERNAL_GROUP));
      }

      logger.debug("Returning JaxbRoles: " + roles);

      // JaxbUser(String userName, String password, String name, String email, String provider, boolean canLogin, JaxbOrganization organization, Set<JaxbRole> roles)
      User user = new JaxbUser(userName, null, displayName, email, PROVIDER_NAME, true, jaxbOrganization, roles);

      userCache.put(userName, user);
      logger.debug("Returning user {}", userName);

      return user;

    } finally {
      currentThread.setContextClassLoader(originalClassloader);
    }

  }

  /*
   ** Verify that the user exists
   ** Query with /direct/user/:ID:/exists
   */
  private boolean verifyBlackboardUser(String userId) {

      logger.debug("verifyBlackboardUser({})", userId);

      try {
        if ((userPattern != null) && !userId.matches(userPattern)) {
          logger.debug("verify user {} failed regexp {}", userId, userPattern);
          return false;
        }
      } catch (PatternSyntaxException e) {
        logger.warn("Invalid regular expression for user pattern {} - disabling checks", userPattern);
        userPattern = null;
      }

      String json = getJsonFromBlackboard(blackboardUrl + "/learn/api/public/v1/users/userName:" + userId + "?fields=id");
      // if user exists json will not be empty
      return StringUtils.isNotBlank(json);
  }

  /*
   ** Verify that the site exists
   ** Query with /direct/site/:ID:/exists
   */
  private boolean verifyBlackboardSite(String siteId) {

      // We could additionally cache positive and negative siteId lookup results here

      logger.debug("verifyBlackboardSite(" + siteId + ")");

      try {
        if ((sitePattern != null) && !siteId.matches(sitePattern)) {
          logger.debug("verify site {} failed regexp {}", siteId, sitePattern);
          return false;
        }
      } catch (PatternSyntaxException e) {
        logger.warn("Invalid regular expression for site pattern {} - disabling checks", sitePattern);
        sitePattern = null;
      }

      String json = getJsonFromBlackboard(blackboardUrl + "/learn/api/public/v1/courses/courseId:" + siteId + "?fields=id");
      // if site exists json will not be empty
      return StringUtils.isNotBlank(json);
  }

  private String[] getBlackboardCourseMemberships(String userId) {
    logger.debug("getBlackboardCourseMemberships(" + userId + ")");
    String nextPage = "/learn/api/public/v1/users/userName:" + userId + "/courses?fields=courseId,courseRoleId";
    List<String> roleList = new ArrayList<String>();

    while (StringUtils.isNotBlank(nextPage)) {
      String json = getJsonFromBlackboard(blackboardUrl + nextPage);
      if (StringUtils.isNotBlank(json)) {
        Gson g = new Gson();
        BlackboardCourseMemberships memberships = g.fromJson(json, BlackboardCourseMemberships.class);
        for (BlackboardCourseMembership membership: memberships.getResults()) {
          logger.debug("courseId: {}, role: {}", membership.getCourseId(), membership.getCourseRoleId());
          String courseId = courseIdCache.getUnchecked(membership.getCourseId());
          String opencastRole = buildOpencastRole(courseId, membership.getCourseRoleId());
          roleList.add(opencastRole);
        }

        BlackboardPaging paging = memberships.getPaging();
        if (paging != null) {
          nextPage = paging.getNextPage();
        } else {
          nextPage = null;
        }
        logger.debug("nextPage: {}", nextPage);

      } else {
        nextPage = null;
      }
    }

    if (roleList.isEmpty()) {
      return null;
    } else {
      return roleList.toArray(new String[0]);
    }
  }

  private String loadCourseIdFromBlackboard(String courseId) {
    logger.debug("In loadCourseIdFromBlackboard, currently processing id : {}", courseId);
    String json = getJsonFromBlackboard(blackboardUrl + "/learn/api/public/v1/courses/" + courseId + "?fields=courseId");
    String friendlyCourseId = "";

    if (StringUtils.isNotBlank(json)) {
      JsonObject course = new JsonParser().parse(json).getAsJsonObject();
      friendlyCourseId = course.get("courseId").getAsString();
      courseIdCache.put(courseId, friendlyCourseId);
      return friendlyCourseId;
    }
    return null;
  }


  /**
   * Get the internal Blackboard provided name and email for the supplied user.
   *
   * @param userId
   * @return
   */
  private String[] getBlackboardUser(String userId) {
    logger.debug("getBlackboardUser({})", userId);

    String json = getJsonFromBlackboard(blackboardUrl + "/learn/api/public/v1/users/userName:" + userId + "?fields=name.given,name.family,contact.email");
    if (StringUtils.isNotBlank(json)) {
      JsonObject user = new JsonParser().parse(json).getAsJsonObject();
      String name = user.getAsJsonObject("name").get("given").getAsString();
      name += " " + user.getAsJsonObject("name").get("family").getAsString();
      String email = user.getAsJsonObject("contact").get("email").getAsString();
      return new String[]{name, email};
    }
    return null;
  }

  private String getJsonFromBlackboard(String url) {
    String json = null;
    try {
      int retries = 0;
      HttpURLConnection connection = null;
      URL connectionUrl = new URL(url);
      while (json == null && getBearerToken() && retries < 3) {
        retries++;

        connection = (HttpURLConnection) connectionUrl.openConnection();
        connection.setRequestMethod("GET");
        connection.setDoOutput(true);
        connection.setRequestProperty("Authorization", "Bearer " + bearerToken);
        connection.setRequestProperty("User-Agent", OC_USERAGENT);

        connection.connect();
        int code = connection.getResponseCode();
        logger.debug("HTTP return code: {} for '{}'", code, url);
        if (code == 401) {
          bearerToken = null;
        } else {
          json = IOUtils.toString(new BufferedInputStream(connection.getInputStream()));
          logger.debug(json);
        }
      }
    } catch (FileNotFoundException fnf) {
      // if the return is 404 it means the user wasn't found
      logger.debug("Blackboard url '{}' not found", url);
    } catch (Exception e) {
      logger.warn("Exception getting '{}' from Blackboard: {}", url, e.getMessage());
    }

    return json;
  }

  private boolean getBearerToken() {
    logger.debug("getBearerToken");
    if (bearerToken == null) {

      String json;

      try {
        URL url = new URL(blackboardUrl + "/learn/api/public/v1/oauth2/token");
        String encoded = Base64.encodeBase64String((appKey + ":" + secret).getBytes("utf8"));

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Authorization", "Basic " + encoded);
        connection.setRequestProperty("User-Agent", OC_USERAGENT);

        OutputStream os = connection.getOutputStream();
        BufferedWriter postData = new BufferedWriter(new OutputStreamWriter(os, "UTF-8"));
        postData.write("grant_type=client_credentials");
        postData.flush();
        postData.close();
        os.close();

        int code = connection.getResponseCode();

        if (code == 401) {
          logger.error("Incorrect app credentials for Backboard");
          return false;
        }

        logger.debug("HTTP return code: {}", code);
        json = IOUtils.toString(new BufferedInputStream(connection.getInputStream()));
        logger.debug(json);

        JsonObject token = new JsonParser().parse(json).getAsJsonObject();
        bearerToken = token.get("access_token").getAsString();
      } catch (Exception e) {
        logger.debug("exception getting bearer token: {}", e);
      }

    }
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.CachingUserProviderMXBean#getCacheHitRatio()
   */
  @Override
  public float getCacheHitRatio() {
    if (requests.get() == 0) {
      return 0;
    }
    return (float) (requests.get() - blackboardLoads.get()) / requests.get();
  }

  /**
   * Build a Opencast role "foo_user" from the given Blackboard locations
   *
   * @param blackboardLocationReference
   * @param blackboardRole
   * @return
   */
  private String buildOpencastRole(String siteId, String blackboardRole) {

    // we need to parse the site id from the reference
    // String siteId = blackboardLocationReference.substring(blackboardLocationReference.indexOf("/", 2) + 1);

    // map Blackboard role to LTI role
    String ltiRole = instructorRoles.contains(blackboardRole) ? LTI_INSTRUCTOR_ROLE : LTI_LEARNER_ROLE;

    return siteId + "_" + ltiRole;
  }

  /**
   * Get a value for for a tag in the element
   *
   * @param sTag
   * @param eElement
   * @return
   */
  private static String getTagValue(String sTag, Element eElement) {
    if (eElement.getElementsByTagName(sTag) == null)
      return null;

    NodeList nlList = eElement.getElementsByTagName(sTag).item(0).getChildNodes();
    Node nValue = nlList.item(0);
    return (nValue != null) ? nValue.getNodeValue() : null;
  }

  @Override
  public Iterator<User> findUsers(String query, int offset, int limit) {

    logger.debug("findUsers(query=" + query + " offset=" + offset + " limit=" + limit + ")");

    if (query == null)
      throw new IllegalArgumentException("Query must be set");

    if (query.endsWith("%")) {
      query = query.substring(0, query.length() - 1);
    }

    if (query.isEmpty()) {
      return Collections.emptyIterator();
    }

    // Verify if a user exists (non-wildcard searches only)
    if (!verifyBlackboardUser(query.toLowerCase())) {
      return Collections.emptyIterator();
    }

    List<User> users = new LinkedList<User>();
    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);
    JaxbUser queryUser = new JaxbUser(query, PROVIDER_NAME, jaxbOrganization, new HashSet<JaxbRole>());
    users.add(queryUser);

    return users.iterator();
  }

  @Override
  public Iterator<User> getUsers() {
    // We never enumerate all users
    return Collections.emptyIterator();
  }

  @Override
  public void invalidate(String userName) {
    userCache.invalidate(userName);
  }

  @Override
  public long countUsers() {
    // Not meaningful, as we never enumerate users
    return 0;
  }

  // RoleProvider methods

   @Override
   public Iterator<Role> getRoles() {

     // We won't ever enumerate all Blackboard sites, so return an empty list here
     return Collections.emptyIterator();
   }

   @Override
   public List<Role> getRolesForUser(String userName) {

      List<Role> roles = new LinkedList<Role>();

      // Don't answer for admin, anonymous or empty user
      if ("admin".equals(userName) || "".equals(userName) || "anonymous".equals(userName)) {
         logger.debug("we don't answer for: " + userName);
         return roles;
      }

      logger.debug("getRolesForUser(" + userName + ")");

      User user = loadUser(userName);
      if (user != null) {
        logger.debug("Returning cached roleset for {}", userName);
        return new ArrayList<Role>(user.getRoles());
      }

     // Not found
     logger.debug("Return empty roleset for {} - not found on Blackboard");
     return new LinkedList<Role>();
   }

   @Override
   public Iterator<Role> findRoles(String query, Role.Target target, int offset, int limit) {

     // We search for SITEID, SITEID_Learner, SITEID_Instructor

     logger.debug("findRoles(query=" + query + " target=" + target + " offset=" + offset + " limit=" + limit + ")");

     // Don't return roles for users or groups
     if (target == Role.Target.USER) {
        return Collections.emptyIterator();
     }

     boolean exact = true;
     boolean ltirole = false;

     if (query.endsWith("%")) {
       exact = false;
       query = query.substring(0, query.length() - 1);
     }

     if (query.isEmpty()) {
        return Collections.emptyIterator();
     }

     // Verify that role name ends with LTI_LEARNER_ROLE or LTI_INSTRUCTOR_ROLE
     if (exact && !query.endsWith("_" + LTI_LEARNER_ROLE) && !query.endsWith("_" + LTI_INSTRUCTOR_ROLE)) {
        return Collections.emptyIterator();
     }

     String blackboardSite = null;

     if (query.endsWith("_" + LTI_LEARNER_ROLE)) {
       blackboardSite = query.substring(0, query.lastIndexOf("_" + LTI_LEARNER_ROLE));
       ltirole = true;
     } else if (query.endsWith("_" + LTI_INSTRUCTOR_ROLE)) {
       blackboardSite = query.substring(0, query.lastIndexOf("_" + LTI_INSTRUCTOR_ROLE));
       ltirole = true;
     }

     if (!ltirole) {
       blackboardSite = query;
     }

     if (!verifyBlackboardSite(blackboardSite)) {
        return Collections.emptyIterator();
     }

     // Roles list
     List<Role> roles = new LinkedList<Role>();

     JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);

     if (ltirole) {
       // Query is for a Site ID and an LTI role (Instructor/Learner)
       roles.add(new JaxbRole(query, jaxbOrganization, "Blackboard Site Role", Role.Type.EXTERNAL));
     } else {
       // Site ID - return both roles
       roles.add(new JaxbRole(blackboardSite + "_" + LTI_INSTRUCTOR_ROLE, jaxbOrganization, "Blackboard Site Instructor Role", Role.Type.EXTERNAL));
       roles.add(new JaxbRole(blackboardSite + "_" + LTI_LEARNER_ROLE, jaxbOrganization, "Blackboard Site Learner Role", Role.Type.EXTERNAL));
     }

     return roles.iterator();
   }

}
