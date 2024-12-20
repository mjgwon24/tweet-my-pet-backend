package tweet_my_pet.tweet_my_pet_backend.restController;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.locationtech.jts.geom.Point;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto;
import tweet_my_pet.tweet_my_pet_backend.entity.Store;
import tweet_my_pet.tweet_my_pet_backend.repository.StoreRepository;
import tweet_my_pet.tweet_my_pet_backend.service.StoreService;

@RestController
@RequestMapping("/api/stores")
public class StoreController {

    private final StoreService storeService;
    private final StoreRepository storeRepository;

    @Autowired
    public StoreController(StoreService storeService, StoreRepository storeRepository) {
        this.storeService = storeService;
        this.storeRepository = storeRepository;
    }

    @PostMapping
    public ResponseEntity<String> saveStore(@RequestBody StoreDto storeDTO) {
        Store store = new Store();
        store.setStoreName(storeDTO.getName());
        store.setStoreTel(storeDTO.getTel());
        store.setStoreLocation(storeDTO.getLocation());
        store.setStorePresidentName(storeDTO.getPresidentName());

        // 위도와 경도로 Point 생성
        Point point = storeService.createPoint(storeDTO.getLatitude(), storeDTO.getLongitude());
        store.setStorePoint(point);

        storeRepository.save(store);
        return ResponseEntity.ok("Store saved successfully!");
    }
}

