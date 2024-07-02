package com.johncarlo.userauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Slf4j
@RequiredArgsConstructor
@Controller
public class UserAuthController {

    private final UserRepository userRepository;
    private final JwtTokenUtil jwtTokenUtil;

    @GetMapping("/login")
    public String login(HttpSession httpSession) {
        String token = (String) httpSession.getAttribute("token");
        if (token != null && jwtTokenUtil.validateToken(token)) {
            User existingUser = userRepository.findByEmail(jwtTokenUtil.getEmailFromToken(token));
            return "redirect:" + (existingUser.getType().equals("admin") ? "/admin-detail" : "/user-detail");
        } else {
            return "login";
        }

    }

    @PostMapping("/login")
    public String loginUser(User user, RedirectAttributes redirectAttributes, HttpSession httpSession) {
        User existingUser = userRepository.findByEmail(user.getEmail());
        if (existingUser != null && user.getPassword().equals(existingUser.getPassword())) {
            String token = jwtTokenUtil.generateToken(existingUser.getEmail());
            httpSession.setAttribute("token", token);
            return "redirect:" + (existingUser.getType().equals("admin") ? "/admin-detail" : "/user-detail");
        } else {
            redirectAttributes.addFlashAttribute("error", "Invalid email or password");
            return "redirect:/login?error";
        }
    }

    @GetMapping("/user-detail")
    public String userDetail(Model model, HttpSession httpSession) {
        String token = (String) httpSession.getAttribute("token");
        if (jwtTokenUtil.validateToken(token)) {
            User user = userRepository.findByEmail(jwtTokenUtil.getEmailFromToken(token));
            model.addAttribute("user", user);
            return "user-detail";
        } else {
            return "redirect:/login";
        }
    }

    @GetMapping("/admin-detail")
    public String adminDetail(Model model, HttpSession httpSession) {
        String token = (String) httpSession.getAttribute("token");
        if (jwtTokenUtil.validateToken(token)) {
            User user = userRepository.findByEmail(jwtTokenUtil.getEmailFromToken(token));
            model.addAttribute("user", user);
            return "admin-detail";
        } else {
            return "redirect:/login";
        }
    }

    @GetMapping("/logout")
    public String logout(HttpSession httpSession) {
        httpSession.removeAttribute("token");
        return "redirect:/login";
    }
}
