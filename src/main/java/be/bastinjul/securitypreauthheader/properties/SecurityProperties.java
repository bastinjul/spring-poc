package be.bastinjul.securitypreauthheader.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.validation.Valid;
import java.util.List;

@ConfigurationProperties(prefix = "be.bastinjul.security.preauth.header")
public record SecurityProperties(List<String> filterPathPatterns,
                                 @Valid List<NoFilterProperties> noFilterPathPatterns) {
}
