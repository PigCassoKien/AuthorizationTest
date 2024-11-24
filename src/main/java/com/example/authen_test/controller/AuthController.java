package com.example.authen_test.controller;

import com.example.authen_test.model.User;
import com.example.authen_test.model.dto.UpdateRoleDto;
import com.example.authen_test.model.dto.UserLoginDto;
import com.example.authen_test.model.dto.UserRegistrationDto;
import com.example.authen_test.repository.UserRepository;
import com.example.authen_test.service.JwtUtil;
import com.example.authen_test.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("api/auth")
public class AuthController {
    @Autowired
    private UserService userService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody UserRegistrationDto userRegistrationDto) {
        if (userRepository.findByUsername(userRegistrationDto.getUsername()).isPresent()) {
            return new ResponseEntity<>("Username already exists", HttpStatus.CONFLICT);
        }

        User user = new User();
        user.setUsername(userRegistrationDto.getUsername());
        user.setPassword(passwordEncoder.encode(userRegistrationDto.getPassword()));
        user.setRole(userRegistrationDto.getRole() != null ? userRegistrationDto.getRole() : "USER");
        userRepository.save(user);
        return new ResponseEntity<>("User registered successfully", HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<String> loginUser(@RequestBody UserLoginDto userLoginDto) {
        Optional<User> userOptional = userRepository.findByUsername(userLoginDto.getUsername());

        if (userOptional.isPresent() && passwordEncoder.matches(userLoginDto.getPassword(), userOptional.get().getPassword())) {
            String jwtToken = jwtUtil.generateToken(userOptional.get());
            return ResponseEntity.ok(jwtToken);
        } else {
            return new ResponseEntity<>("Invalid Username or password", HttpStatus.UNAUTHORIZED);
        }

    }
    @PutMapping("/update-role")
    public ResponseEntity<String> updateUserRole(@RequestBody UpdateRoleDto updateRoleDto) {
        User currentUser = userService.getCurrentUser();
        if (currentUser == null) {
            return new ResponseEntity<>("Unauthorized access", HttpStatus.UNAUTHORIZED);
        }
        if ("SUPERADMIN".equals(currentUser.getRole())) {
            Optional<User> userToUpdateOptional = userRepository.findByUsername(updateRoleDto.getUsername());
            if (userToUpdateOptional.isPresent()) {
                User userToUpdate = userToUpdateOptional.get();
                userToUpdate.setRole(updateRoleDto.getNewRole());
                userRepository.save(userToUpdate);
                return new ResponseEntity<>("User role updated successfully", HttpStatus.OK);

            } else {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }
        } else {
            return new ResponseEntity<>("Unauthorized access",HttpStatus.UNAUTHORIZED);
        }
    }

    private final Set<String> tokenBlacklist = ConcurrentHashMap.newKeySet();

    @PostMapping("/logout")
    public ResponseEntity<String> logoutUser(@RequestHeader("Authorization") String token) {
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        tokenBlacklist.add(token);
        return new ResponseEntity<>("User logged out successfully", HttpStatus.OK);
    }

    //Phuong thuc dung de kiem tra tai khoan da bi log out chua
    public boolean isTokenBlacklisted(String token) {
        return tokenBlacklist.contains(token);
    }

    @DeleteMapping("/delete/{username}")
    public ResponseEntity<String> deleteUser(@PathVariable String username) {
        User currentUser = userService.getCurrentUser();
        if (currentUser == null) {
            return new ResponseEntity<>("Unauthorized access", HttpStatus.UNAUTHORIZED);
        }
        if ("SUPERADMIN".equals(currentUser.getRole())) {
            Optional<User> userToDeleteOptional = userRepository.findByUsername(username);
            if (userToDeleteOptional.isPresent()) {
                User userToDelete = userToDeleteOptional.get();
                userRepository.delete(userToDelete);
                return new ResponseEntity<>("User deleted successfully", HttpStatus.OK);
            } else {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }
        } else {
            return new ResponseEntity<>("Unauthorized access",HttpStatus.UNAUTHORIZED);
        }
    }
}
