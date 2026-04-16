package id.ac.ui.cs.advprog.mysawit.modules.auth.dto;

import id.ac.ui.cs.advprog.mysawit.core.model.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterRequest {
    @NotBlank @Email
    private String email;

    @NotBlank
    private String username;

    @NotBlank @Size(min = 8)
    private String password;

    @NotNull
    private Role role;
}