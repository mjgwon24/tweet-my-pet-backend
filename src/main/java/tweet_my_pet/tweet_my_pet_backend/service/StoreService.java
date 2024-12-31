package tweet_my_pet.tweet_my_pet_backend.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.geo.Point;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto.FetchStoresResponse;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto.FetchStoresResponse.FetchedStore;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto.CreateStoreRequest;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto.FetchStoreResponse;
import tweet_my_pet.tweet_my_pet_backend.dto.room.RoomDto.FetchRoomResponse;
import tweet_my_pet.tweet_my_pet_backend.dto.store.StoreFeatureDto.FetchStoreFeatureResponse;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.StoreCategory;
import tweet_my_pet.tweet_my_pet_backend.entity.room.Room;
import tweet_my_pet.tweet_my_pet_backend.entity.store.Store;
import tweet_my_pet.tweet_my_pet_backend.repository.StoreRepository;

import java.util.Comparator;
import java.util.List;

import static tweet_my_pet.tweet_my_pet_backend.util.PointUtil.calculateDistanceSpacing;
import static tweet_my_pet.tweet_my_pet_backend.util.StoreFeatureUtil.storeFeatureListToString;

@RequiredArgsConstructor
@Service
public class StoreService {
    private final StoreRepository storeRepository;

    // 매장 추가
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
                .isSmallDog(savedStore.getStoreFeature().getIsSmallDog())
                .isMediumDog(savedStore.getStoreFeature().getIsMediumDog())
                .isLargeDog(savedStore.getStoreFeature().getIsLargeDog())
                .isParking(savedStore.getStoreFeature().getIsParking())
                .isDogPark(savedStore.getStoreFeature().getIsDogPark())
                .isDogSwimmingPool(savedStore.getStoreFeature().getIsDogSwimmingPool())
                .isInternet(savedStore.getStoreFeature().getIsInternet())
                .isBarbecue(savedStore.getStoreFeature().getIsBarbecue())
                .isToiletDivision(savedStore.getStoreFeature().getIsToiletDivision())
                .isFoodPacking(savedStore.getStoreFeature().getIsFoodPacking())
                .isWaitingPlace(savedStore.getStoreFeature().getIsWaitingPlace())
                .isKidSeat(savedStore.getStoreFeature().getIsKidSeat())
                .build();

        return FetchStoreResponse.builder()
                .id(savedStore.getId())
                .storeName(savedStore.getStoreName())
                .storeTel(savedStore.getStoreTel())
                .storeLocation(savedStore.getStoreLocation())
                .storePoint(savedStore.getStorePoint())
                .storePresidentName(savedStore.getStorePresidentName())
                .storeCategory(savedStore.getStoreCategory())
                .rating(savedStore.getRating())
                .reviewCount(savedStore.getReviewCount())
                .petGuide(savedStore.getPetGuide())
                .useGuide(savedStore.getUseGuide())
                .feature(fetchStoreFeatureResponse)
                .rooms(rooms)
                .build();
    }

    /**
     * 매장 카테고리, 정렬 별 매장 목록 조회
     * @param inputSort: distance, rating 만 허용
     */
    public FetchStoresResponse fetchStoresByStoreCategoryAndArray(StoreCategory storeCategory, String inputSort, Point myPoint, int pageNumber, int size) {
        List<FetchedStore> fetchedStores;
        int totalElements = storeRepository.findByStoreCategoryAll(storeCategory).size();
        int totalPages = (int) Math.ceil((double) totalElements / size);

        if ("distance".equalsIgnoreCase(inputSort)) {
            List<Store> stores = storeRepository.findByStoreCategoryAll(storeCategory);

            fetchedStores = stores.stream()
                    .map(store -> FetchedStore.builder()
                            .id(store.getId())
                            .storeName(store.getStoreName())
                            .location(store.getStoreLocation())
                            .longitude(store.getStorePoint().getX())
                            .latitude(store.getStorePoint().getY())
                            .storeCategory(store.getStoreCategory())
                            .rating(store.getRating())
                            .reviewCount(store.getReviewCount())
                            .thumbPath(store.getThumbPath())
                            .distanceSpacing(calculateDistanceSpacing(myPoint, store.getStorePoint()))
                            .feature(storeFeatureListToString(store.getStoreFeature()))
                            .lowerPrice(store.getRooms() != null && !store.getRooms().isEmpty()
                                    ? store.getRooms().stream().mapToInt(Room::getPricePerNight).min().orElse(0)
                                    : 0)
                            .build())
                    .sorted(Comparator.comparingDouble(FetchedStore::distanceSpacing))
                    .toList();

            int start = pageNumber * size;
            int end = Math.min(start + size, fetchedStores.size());
            fetchedStores = fetchedStores.subList(start, end);
        } else {
            Sort sort = Sort.by(Sort.Direction.DESC, inputSort);
            PageRequest pageRequest = PageRequest.of(pageNumber, size, sort);

            Page<Store> stores = storeRepository.findByStoreCategory(storeCategory, pageRequest);

            fetchedStores = stores.getContent().stream()
                    .map(store -> FetchedStore.builder()
                            .id(store.getId())
                            .storeName(store.getStoreName())
                            .location(store.getStoreLocation())
                            .longitude(store.getStorePoint().getX())
                            .latitude(store.getStorePoint().getY())
                            .storeCategory(store.getStoreCategory())
                            .rating(store.getRating())
                            .reviewCount(store.getReviewCount())
                            .thumbPath(store.getThumbPath())
                            .distanceSpacing(calculateDistanceSpacing(myPoint, store.getStorePoint()))
                            .feature(storeFeatureListToString(store.getStoreFeature()))
                            .build())
                    .toList();

            totalElements = (int) stores.getTotalElements();
            totalPages = stores.getTotalPages();
        }

        return FetchStoresResponse.builder()
                .stores(fetchedStores)
                .currentPage(pageNumber)
                .totalPages(totalPages)
                .totalElements((long) totalElements)
                .build();
    }


}

