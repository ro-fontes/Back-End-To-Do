package br.com.rofontes.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.rofontes.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    var servletPath = request.getServletPath();

    if (servletPath.startsWith("/tasks/")) {

      var authorization = request.getHeader("Authorization");

      if (authorization == null) {
        response.sendError(401, "Permission denied (username or password not provided)");
        return;
      }

      var authEncoded = authorization.substring("Basic".length()).trim();

      byte[] authDecode = Base64.getDecoder().decode(authEncoded);

      var authString = new String(authDecode);

      String[] credentials = authString.split(":");

      String username = credentials[0];
      String password = credentials[1];

      var user = this.userRepository.findByUsername(username);

      if (user == null || password == null) {
        response.sendError(401, "Permission denied");
      } else {
        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

        if (passwordVerify.verified) {
          request.setAttribute("idUser", user.getId());
          filterChain.doFilter(request, response);
        } else {
          response.sendError(401, "Permission denied");
        }
      }
    } else {
      filterChain.doFilter(request, response);
    }
  }
}
