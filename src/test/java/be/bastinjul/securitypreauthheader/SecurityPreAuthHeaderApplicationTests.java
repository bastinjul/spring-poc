package be.bastinjul.securitypreauthheader;

import be.bastinjul.securitypreauthheader.filters.HeaderPresenceFilter;
import be.bastinjul.securitypreauthheader.utils.JwtUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityPreAuthHeaderApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void shouldFilterTest() throws Exception {
        this.mockMvc.perform(get("/notSecured"))
                .andExpect(status().isForbidden());
        this.mockMvc.perform(get("/noFilter/test"))
                .andExpect(status().isOk());
        this.mockMvc.perform(get("/secured")
                .header(HeaderPresenceFilter.CUSTOM_HEADER, JwtUtils.constructJwt("test", "info", List.of("role1", "role2"))))
                .andExpect(status().isOk());
        this.mockMvc.perform(get("/notSecured")
                        .header(HeaderPresenceFilter.CUSTOM_HEADER, JwtUtils.constructJwt("test", "info", List.of("role1", "role2"))))
                .andExpect(status().isForbidden());
    }

}
