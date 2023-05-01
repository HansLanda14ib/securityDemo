package ma.projet.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AccountController {

	@GetMapping("/myAccount")
	public String getAccountDetails() {
		return "account";
	}

}
