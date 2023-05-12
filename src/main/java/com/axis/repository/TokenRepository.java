package com.axis.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.axis.token.Token;

public interface TokenRepository extends JpaRepository<Token, Integer> {
	
//	method allow us to get all tokens
	
	@Query("""
			select t from Token t inner join User u on t.user.id = u.id 
			where u.id =:userId and (t.expired = false or t.revoked =false)			
			""")
	List<Token> findAllValidTokensByUser(Integer userId);
//	finding tokens by token
	
Optional<Token> findByToken(String token);
}
