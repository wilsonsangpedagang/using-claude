package id.ac.ui.cs.advprog.mysawit.modules.auth.service;

import id.ac.ui.cs.advprog.mysawit.core.model.Role;
import id.ac.ui.cs.advprog.mysawit.core.model.User;
import id.ac.ui.cs.advprog.mysawit.modules.auth.dto.AuthResponse;
import id.ac.ui.cs.advprog.mysawit.modules.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.mysawit.modules.auth.dto.RegisterRequest;
import id.ac.ui.cs.advprog.mysawit.modules.auth.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private AuthServiceImpl authService;

    private User laborer;

    @BeforeEach
    void setUp() {
        laborer = new User();
        laborer.setId(1L);
        laborer.setEmail("laborer@test.com");
        laborer.setUsername("laborer1");
        laborer.setPassword("hashed");
        laborer.setRole(Role.LABORER);
    }

    // --- register ---

    @Test
    void register_savesUserAndReturnsResponse() {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("laborer@test.com");
        req.setUsername("laborer1");
        req.setPassword("Harvest123!");
        req.setRole(Role.LABORER);

        when(userRepository.findByEmail("laborer@test.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Harvest123!")).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenReturn(laborer);

        AuthResponse response = authService.register(req);

        assertThat(response.getUsername()).isEqualTo("laborer1");
        assertThat(response.getRole()).isEqualTo(Role.LABORER);
        verify(userRepository).save(any(User.class));
    }

    @Test
    void register_throwsWhenEmailAlreadyExists() {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("laborer@test.com");
        req.setUsername("laborer1");
        req.setPassword("Harvest123!");
        req.setRole(Role.LABORER);

        when(userRepository.findByEmail("laborer@test.com")).thenReturn(Optional.of(laborer));

        assertThatThrownBy(() -> authService.register(req))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already registered");
    }

    // --- login ---

    @Test
    void login_authenticatesAndCreatesSession() {
        LoginRequest req = new LoginRequest();
        req.setEmail("laborer@test.com");
        req.setPassword("Harvest123!");

        Authentication auth = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(auth);

        HttpServletRequest httpRequest = mock(HttpServletRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(httpRequest.getSession(false)).thenReturn(null);
        when(httpRequest.getSession(true)).thenReturn(session);
        when(userRepository.findByEmail("laborer@test.com")).thenReturn(Optional.of(laborer));

        AuthResponse response = authService.login(req, httpRequest);

        assertThat(response.getUsername()).isEqualTo("laborer1");
        assertThat(response.getRole()).isEqualTo(Role.LABORER);
        verify(authenticationManager).authenticate(any());
    }

    // --- currentSession ---

    @Test
    void currentSession_returnsUserDetails() {
        when(userRepository.findByEmail("laborer@test.com")).thenReturn(Optional.of(laborer));

        AuthResponse response = authService.currentSession("laborer@test.com");

        assertThat(response.getUsername()).isEqualTo("laborer1");
        assertThat(response.getRole()).isEqualTo(Role.LABORER);
    }

    @Test
    void currentSession_throwsWhenUserNotFound() {
        when(userRepository.findByEmail("unknown@test.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.currentSession("unknown@test.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("User not found");
    }
}
