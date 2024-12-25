package tweet_my_pet.tweet_my_pet_backend.restController;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto.FetchStoresRequest;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto.FetchStoresResponse;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto.CreateStoreRequest;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto.FetchStoreResponse;
import tweet_my_pet.tweet_my_pet_backend.dto.common.ResponseDto;
import tweet_my_pet.tweet_my_pet_backend.service.StoreService;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/store")
public class StoreRestController {
    private final StoreService storeService;

    // 매장 저장
    @PostMapping("/save")
    public ResponseEntity<ResponseDto<FetchStoreResponse>> saveStore(@RequestBody CreateStoreRequest createStoreRequest) {
        FetchStoreResponse fetchStoreResponse = storeService.createStore(createStoreRequest);
        return new ResponseEntity<>(
                new ResponseDto<>(ResponseDto.Status.SUCCESS, "매장 저장 성공", fetchStoreResponse),
                HttpStatus.OK
        );
    }

    // 매장 목록 조회
    @GetMapping("/list")
    public ResponseEntity<ResponseDto<FetchStoresResponse>> fetchStores(@RequestBody FetchStoresRequest fetchStoresRequest) {
        FetchStoresResponse fetchStoreResponse = storeService.fetchStoresByStoreCategoryAndArray(
                fetchStoresRequest.storeCategory(),
                fetchStoresRequest.sort(),
                fetchStoresRequest.point(),
                fetchStoresRequest.pageNumber(),
                fetchStoresRequest.size()
        );

        return new ResponseEntity<>(
                new ResponseDto<>(ResponseDto.Status.SUCCESS, "매장 목록 조회 성공", fetchStoreResponse),
                HttpStatus.OK
        );
    }
}

