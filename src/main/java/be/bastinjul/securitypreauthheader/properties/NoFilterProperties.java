package be.bastinjul.securitypreauthheader.properties;

import org.springframework.http.HttpMethod;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;

@Validated
public record NoFilterProperties(@NotNull String pathPattern,
                                 HttpMethod httpMethod) {
}
