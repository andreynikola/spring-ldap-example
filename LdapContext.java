package paysys.console.utils;

import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import paysys.console.admin.AuthException;
import paysys.persist.Config;
import paysys.persist.dao.AccountRepository;
import paysys.persist.domain.Account;

import javax.annotation.PostConstruct;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.persistence.NoResultException;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

@Slf4j
@Service
public class LdapContext {

    private String url;
    private String base;
    private String distinguishedName;
    private String password;

    public static final String LDAP_USER_BASE = "OU=users, DC=test, DC=com";

    @Autowired
    private Config config;

    @Autowired
    private AccountRepository accountRepository;

    @PostConstruct
    private void init(){
        url = config.getProperty("ldap", "url", "ldap://127.0.0.1:389");
        base = config.getProperty("ldap", "base-dn", "DC=test,DC=com");
        distinguishedName = config.getProperty("ldap", "distinguished-name", "CN=admin,OU=technical,DC=test,DC=com");
        password = config.getProperty("ldap", "password", "qwerty");
    }

    public Boolean contextSource(String userName, String userPassword) throws Exception {

        LdapContextSource contextSource = new LdapContextSource();

        try {
            contextSource.setUrl(url);
            contextSource.setBase(base);
            contextSource.setUserDn(distinguishedName);
            contextSource.setPassword(password);
            contextSource.afterPropertiesSet();

            LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
            ldapTemplate.setIgnorePartialResultException(true);
            ldapTemplate.afterPropertiesSet();

            Filter filter = new EqualsFilter("sAMAccountName", userName);
            boolean authed = ldapTemplate.authenticate("", filter.encode(), userPassword);

            if (!authed) {
                log.debug("LDAP failed authorization for user with username: " + userName);
                return false;
            }

            log.debug("LDAP successful authorization for user with username: " + userName);

            Map<String, String> attributes = new HashMap<>();

            ldapTemplate.search(
                query().where("sAMAccountName").is("user"),
                new AttributesMapper<String>() {
                    public String mapFromAttributes(Attributes attrs) throws NamingException {
                        attributes.put("cn", attrs.get("cn").get().toString());
                        attributes.put("info", attrs.get("info").get().toString());
                        attributes.put("telephoneNumber", attrs.get("telephoneNumber").get().toString());
                        attributes.put("l", attrs.get("l").get().toString());
                        attributes.put("mail", attrs.get("mail").get().toString());
                        attributes.put("userPrincipalName", attrs.get("userPrincipalName").get().toString());
                        attributes.put("useraccountcontrol", attrs.get("useraccountcontrol").get().toString());
                        return attributes.toString();
                    }
                });

            log.debug("LDAP user attributes: " + attributes);

        } catch (Exception e){
            log.error("LDAP authorization error: " + e.getMessage());
            throw new AuthException("LDAP Authorization error", true, true);
        }

        return true;
    }
}
