package tweet_my_pet.tweet_my_pet_backend.restController;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.locationtech.jts.geom.Point;
import tweet_my_pet.tweet_my_pet_backend.dto.CompanyDto;
import tweet_my_pet.tweet_my_pet_backend.entity.Store;
import tweet_my_pet.tweet_my_pet_backend.repository.CompanyRepository;
import tweet_my_pet.tweet_my_pet_backend.service.CompanyService;

@RestController
@RequestMapping("/api/companies")
public class CompanyController {

    private final CompanyService companyService;
    private final CompanyRepository companyRepository;

    @Autowired
    public CompanyController(CompanyService companyService, CompanyRepository companyRepository) {
        this.companyService = companyService;
        this.companyRepository = companyRepository;
    }

    @PostMapping
    public ResponseEntity<String> saveCompany(@RequestBody CompanyDto companyDTO) {
        Store store = new Store();
        store.setCompanyName(companyDTO.getName());
        store.setCompanyTel(companyDTO.getTel());
        store.setCompanyLocation(companyDTO.getLocation());
        store.setCompanyPresidentName(companyDTO.getPresidentName());

        // 위도와 경도로 Point 생성
        Point point = companyService.createPoint(companyDTO.getLatitude(), companyDTO.getLongitude());
        store.setCompanyPoint(point);

        companyRepository.save(store);
        return ResponseEntity.ok("Company saved successfully!");
    }
}

