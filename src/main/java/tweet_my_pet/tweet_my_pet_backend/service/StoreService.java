package tweet_my_pet.tweet_my_pet_backend.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto.CreateStoreRequest;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto.FetchStoreResponse;
import tweet_my_pet.tweet_my_pet_backend.dto.room.RoomDto.FetchRoomResponse;
import tweet_my_pet.tweet_my_pet_backend.dto.store.StoreFeatureDto.FetchStoreFeatureResponse;
import tweet_my_pet.tweet_my_pet_backend.entity.store.Store;
import tweet_my_pet.tweet_my_pet_backend.repository.StoreRepository;

import java.util.List;

@RequiredArgsConstructor
@Service
public class StoreService {
    private final StoreRepository storeRepository;

    /**
     * 매장 추가
     * @param createStoreRequest
     */
    @Transactional
    public FetchStoreResponse createStore(CreateStoreRequest createStoreRequest) {
        Store savedStore = storeRepository.save(createStoreRequest.toEntity());

        // room 응답 생성
        List<FetchRoomResponse> rooms = savedStore.getRooms().stream()
                .map(room -> FetchRoomResponse.builder()
                        .id(room.getId())
                        .roomType(room.getRoomType())
                        .pricePerNight(room.getPricePerNight())
                        .totalRoomCount(room.getTotalRoomCount())
                        .build())
                .toList();

        // storeFeature 응답 생성
        FetchStoreFeatureResponse fetchStoreFeatureResponse = FetchStoreFeatureResponse.builder()
                .id(savedStore.getStoreFeature().getId())
                .acceptPetSizes(savedStore.getStoreFeature().getAcceptPetSizes())
                .isParking(savedStore.getStoreFeature().getIsParking())
                .isDogPark(savedStore.getStoreFeature().getIsDogPark())
                .isDogSwimmingPool(savedStore.getStoreFeature().getIsDogSwimmingPool())
                .isInternet(savedStore.getStoreFeature().getIsInternet())
                .isBarbecue(savedStore.getStoreFeature().getIsBarbecue())
                .build();

        return FetchStoreResponse.builder()
                .id(savedStore.getId())
                .storeName(savedStore.getStoreName())
                .storeTel(savedStore.getStoreTel())
                .storeLocation(savedStore.getStoreLocation())
                .storePoint(savedStore.getStorePoint())
                .storePresidentName(savedStore.getStorePresidentName())
                .rating(savedStore.getRating())
                .reviewCount(savedStore.getReviewCount())
                .petGuide(savedStore.getPetGuide())
                .useGuide(savedStore.getUseGuide())
                .feature(fetchStoreFeatureResponse)
                .rooms(rooms)
                .build();
    }
}

