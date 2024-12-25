package tweet_my_pet.tweet_my_pet_backend.repository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.StoreCategory;
import tweet_my_pet.tweet_my_pet_backend.entity.store.Store;

import java.util.List;

public interface StoreRepository extends JpaRepository<Store, Long> {
    Page<Store> findByStoreCategory(StoreCategory storeCategory, PageRequest pageRequest);

    // category별 매장 목록 전체 조회
    @Query("select s from Store s where s.storeCategory = :storeCategory")
    List<Store> findByStoreCategoryAll(StoreCategory storeCategory);
}
