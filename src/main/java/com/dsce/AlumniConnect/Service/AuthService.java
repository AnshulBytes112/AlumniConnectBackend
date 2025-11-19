package com.dsce.AlumniConnect.Service;

import com.dsce.AlumniConnect.DTO.AuthResponse;
import com.dsce.AlumniConnect.DTO.GoogleSignUpRequest;
import com.dsce.AlumniConnect.DTO.LogInRequest;
import com.dsce.AlumniConnect.DTO.SignUpRequest;
import com.dsce.AlumniConnect.entity.User;
import com.dsce.AlumniConnect.Repository.UserRepository;
import com.dsce.AlumniConnect.utils.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final GoogleTokenVerifier googleTokenVerifier;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;  // Add this
    private final AuthenticationManager authenticationManager;

    public AuthResponse login(LogInRequest request) {
        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            // Get user details
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Check if user registered with Google
            if (user.getAuthProvider() == User.AuthProvider.GOOGLE) {
                throw new RuntimeException("This account was registered with Google. Please use Google Sign-In.");
            }

            // Generate JWT token
            String token = jwtUtils.generateToken(user.getEmail());

            return new AuthResponse(
                    user.getId(),
                    user.getFirstName(),
                    user.getLastName(),
                    user.getEmail(),
                    user.getProfilePicture(),
                    token
            );

        } catch (BadCredentialsException e) {
            throw new RuntimeException("Invalid email or password");
        }
    }


    public AuthResponse signup(SignUpRequest request) {
        // Check if user already exists
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email already registered");
        }

        // Create new user
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(User.Role.USER);
        user.setAuthProvider(User.AuthProvider.LOCAL);
        user.setGraduationYear(request.getGraduationYear());
        user.setDepartment(request.getDepartment());
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());

        userRepository.save(user);

        // Generate JWT token
        String token = jwtUtils.generateToken(user.getEmail());

        return new AuthResponse(
                user.getId(),
                user.getFirstName(),
                user.getLastName(),
                user.getEmail(),
                user.getProfilePicture(),
                token
        );
    }

    public AuthResponse googleLogin(GoogleSignUpRequest googleSignUpRequest) {

        try {
            // STEP 1: Verify Google token
            var payload = googleTokenVerifier.verify(googleSignUpRequest.getIdToken());
            String email = payload.getEmail();
            String firstname = (String) payload.get("First Name");
            String lastname = (String) payload.get("Last Name");
            String name = firstname + " " + lastname;
            String picture = (String) payload.get("picture");

            // STEP 2: Check if user already exists
            User user = userRepository.findByEmail(email).orElse(null);

            // STEP 3: If new user → create a profile
            if (user == null) {
                user = new User();
                user.setEmail(email);
                user.setFirstName(firstname);
                user.setLastName(lastname);
                user.setProfilePicture(picture);
                user.setAuthProvider(User.AuthProvider.GOOGLE);       // mark as Google signup
                user.setPassword(null);         // no password needed
                userRepository.save(user);
            }

            // STEP 4: Generate your own JWT token
            String token = jwtUtils.generateToken(user.getEmail());

            // STEP 5: Return a clean response
            return new AuthResponse(
                    user.getId(),
                   user.getFirstName(),
                    user.getLastName(),
                    user.getEmail(),
                    user.getProfilePicture(),
                    token
            );

        } catch (Exception e) {
            throw new RuntimeException("Google login failed: " + e.getMessage());
        }
    }
}
