package com.axis.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.axis.config.JwtService;
import com.axis.model.Role;
import com.axis.model.User;
import com.axis.repository.TokenRepository;
import com.axis.repository.UserRepository;
import com.axis.token.Token;
import com.axis.token.TokenType;

import lombok.RequiredArgsConstructor;
@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final UserRepository userRepository;
  private final TokenRepository tokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public AuthenticationResponse register(RegisterRequest request) {
    var user = User.builder()
        .firstName(request.getFirstName())
        .lastName(request.getLastName())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(Role.Customer)
        .build();
   var savedUser =  userRepository.save(user);
    var jwtToken = jwtService.generateToken(user);
    
//    persisiting token into token table by using below method
    saveUserToken(savedUser, jwtToken);
//    Here we saved token while registering 
    		
    return AuthenticationResponse.builder()
        .token(jwtToken)
        .build();
  }


  public AuthenticationResponse authenticate(AuthenticationRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );
    var user = userRepository.findByEmail(request.getEmail())
        .orElseThrow();
    var jwtToken = jwtService.generateToken(user);
    
    revokeallUserTokens(user);
    
    saveUserToken(user, jwtToken);
    return AuthenticationResponse.builder()
        .token(jwtToken)
        .build();
  }
//  by implementing this method we are removing multiple tokens for single user
  private void revokeallUserTokens(User user) {
	  var ValidTokens = tokenRepository.findAllValidTokensByUser(user.getId());
	  if(ValidTokens.isEmpty())
		  return;
//	  t refers to token 
	  ValidTokens.forEach(t->
	  {
		  t.setExpired(true);
		  t.setRevoked(true);
		  
	  });
	  
	  tokenRepository.saveAll(ValidTokens);
  }
  
//persisiting token into token table by using below method

private void saveUserToken(User user, String jwtToken) {
	var token =Token.builder()
    		.user(user)
    		.token(jwtToken)
    		.tokenType(TokenType.BEARER)
    		.revoked(false)
    		.expired(false)
    		.build();
    		
    tokenRepository.save(token);
}
}